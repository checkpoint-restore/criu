#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/falloc.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/userfaultfd.h>
#include <time.h>
#include <string.h>
#include <pthread.h>
#include <poll.h>
#include <lz4.h>

#undef LOG_PREFIX
#define LOG_PREFIX "page-xfer: "

#include "types.h"
#include "cr_options.h"
#include "servicefd.h"
#include "image.h"
#include "page-xfer.h"
#include "page-pipe.h"
#include "util.h"
#include "protobuf.h"
#include "images/pagemap.pb-c.h"
#include "fcntl.h"
#include "pstree.h"
#include "parasite-syscall.h"
#include "rst_info.h"
#include "stats.h"
#include "tls.h"
#include "uffd.h"
#include "cow-dump.h"
#include "criu-plugin.h"
#include "plugin.h"
#include "dump.h"
#include "mem.h"
#include "atomic-bitmap.h"
#include "cow-bitmap.h"
#include "spsc-queue.h"

static int page_server_sk = -1;
static bool bulk_stream_done = false;

bool page_server_bulk_stream_done(void)
{
	return bulk_stream_done;
}

#define BULK_STREAM_WOULD_BLOCK 0
#define BULK_STREAM_PROGRESS 1
#define BULK_STREAM_COMPLETE 2
/* No ACK on bulk close: end-of-stream marker is enough. */

/* Global compression statistics for stats printing */
static unsigned long g_compress_uncompressed_bytes = 0;
static unsigned long g_compress_compressed_bytes = 0;

struct page_server_iov {
	u32 cmd;
	u64 nr_pages;
	u64 vaddr;
	u64 dst_id;
};

static void psi2iovec(struct page_server_iov *ps, struct iovec *iov)
{
	iov->iov_base = decode_pointer(ps->vaddr);
	iov->iov_len = ps->nr_pages * PAGE_SIZE;
}

#define PS_IOV_ADD    1
#define PS_IOV_HOLE   2
#define PS_IOV_OPEN   3
#define PS_IOV_OPEN2  4
#define PS_IOV_PARENT 5
#define PS_IOV_ADD_F  6
#define PS_IOV_GET    7
#define PS_IOV_GET_ALL 8
#define PS_IOV_ADD_F_PF 9
#define PS_IOV_ADD_F_COMPRESS 10

#define PS_IOV_CLOSE	   0x1023

/* Compression state machine states for bulk stream reader */
enum compress_read_state {
	COMPRESS_STATE_READING_HEADER = 0,    /* Reading page_server_iov header */
	COMPRESS_STATE_READING_SIZE,          /* Reading compressed_size (4 bytes) */
	COMPRESS_STATE_READING_COMPRESSED,    /* Reading compressed data */
	COMPRESS_STATE_READING_UNCOMPRESSED,  /* Reading uncompressed page data */
};
#define PS_IOV_FORCE_CLOSE 0x1024

#define PS_CMD_BITS 16
#define PS_CMD_MASK ((1 << PS_CMD_BITS) - 1)

#define PS_TYPE_BITS 8
#define PS_TYPE_MASK ((1 << PS_TYPE_BITS) - 1)

#define PS_TYPE_PID   (1)
#define PS_TYPE_SHMEM (2)
/*
 * XXX: When adding new types here check decode_pm for legacy
 * numbers that can be met from older CRIUs
 */

static inline u64 encode_pm(int type, unsigned long id)
{
	if (type == CR_FD_PAGEMAP)
		type = PS_TYPE_PID;
	else if (type == CR_FD_SHMEM_PAGEMAP)
		type = PS_TYPE_SHMEM;
	else {
		BUG();
		return 0;
	}

	return ((u64)id) << PS_TYPE_BITS | type;
}

static int decode_pm(u64 dst_id, unsigned long *id)
{
	int type;

	/*
	 * Magic numbers below came from the older CRIU versions that
	 * erroneously used the changing CR_FD_* constants. The
	 * changes were made when we merged images together and moved
	 * the CR_FD_-s at the tail of the enum
	 */
	type = dst_id & PS_TYPE_MASK;
	switch (type) {
	case 10: /* 3.1 3.2 */
	case 11: /* 1.3 1.4 1.5 1.6 1.7 1.8 2.* 3.0 */
	case 16: /* 1.2 */
	case 17: /* 1.0 1.1 */
	case PS_TYPE_PID:
		*id = dst_id >> PS_TYPE_BITS;
		type = CR_FD_PAGEMAP;
		break;
	case 27: /* 1.3 */
	case 28: /* 1.4 1.5 */
	case 29: /* 1.6 1.7 */
	case 32: /* 1.2 1.8 */
	case 33: /* 1.0 1.1 3.1 3.2 */
	case 34: /* 2.* 3.0 */
	case PS_TYPE_SHMEM:
		*id = dst_id >> PS_TYPE_BITS;
		type = CR_FD_SHMEM_PAGEMAP;
		break;
	default:
		type = -1;
		break;
	}

	return type;
}

static inline u32 encode_ps_cmd(u32 cmd, u32 flags)
{
	return flags << PS_CMD_BITS | cmd;
}

static inline u32 decode_ps_cmd(u32 cmd)
{
	return cmd & PS_CMD_MASK;
}

static inline u32 decode_ps_flags(u32 cmd)
{
	return cmd >> PS_CMD_BITS;
}

static inline int __send(int sk, const void *buf, size_t sz, int fl)
{
	return opts.tls ? tls_send(buf, sz, fl) : send(sk, buf, sz, fl);
}

static inline int __recv(int sk, void *buf, size_t sz, int fl)
{
	return opts.tls ? tls_recv(buf, sz, fl) : recv(sk, buf, sz, fl);
}

static inline int send_psi_flags(int sk, struct page_server_iov *pi, int flags)
{
	if (__send(sk, pi, sizeof(*pi), flags) != sizeof(*pi)) {
		pr_perror("Can't send PSI %d to server", pi->cmd);
		return -1;
	}
	return 0;
}

static inline int send_psi(int sk, struct page_server_iov *pi)
{
	return send_psi_flags(sk, pi, 0);
}

/*
 * Send a page with LZ4 compression.
 * Protocol: header (PS_IOV_ADD_F_COMPRESS) + compressed_size (4 bytes) + compressed_data
 * Optimized: single buffer, single send() syscall
 */
static __maybe_unused int send_page_compressed(int sk, const void *data, u64 dst_id,
					      unsigned long vaddr)
{
	/* Buffer layout: [header][compressed_size][compressed_data] */
	char send_buf[sizeof(struct page_server_iov) + sizeof(int) + LZ4_compressBound(PAGE_SIZE)];
	struct page_server_iov *pi = (struct page_server_iov *)send_buf;
	int *compressed_size = (int *)(send_buf + sizeof(*pi));
	char *compressed_data = send_buf + sizeof(*pi) + sizeof(int);
	int total_len;
	int ret;

	/* 1. Compress directly into send buffer (no memcpy!) */
	*compressed_size = LZ4_compress_default(data, compressed_data, PAGE_SIZE, 
						LZ4_compressBound(PAGE_SIZE));
	if (*compressed_size <= 0) {
		pr_err("LZ4 compression failed for page at %lx\n", vaddr);
		return -1;
	}

	/* Track compression statistics */
	g_compress_uncompressed_bytes += PAGE_SIZE;
	g_compress_compressed_bytes += *compressed_size;

	pr_debug("Compressed page at %lx: %lu -> %d bytes (%.1f%%)\n", 
		 vaddr, PAGE_SIZE, *compressed_size, 
		 (float)(*compressed_size) * 100 / PAGE_SIZE);

	/* 2. Fill in header (after compression so we know it succeeded) */
	pi->cmd = encode_ps_cmd(PS_IOV_ADD_F_COMPRESS, PE_PRESENT);
	pi->nr_pages = 1;
	pi->vaddr = vaddr;
	pi->dst_id = dst_id;

	/* 3. Single send: header + size + compressed data */
	total_len = sizeof(*pi) + sizeof(int) + *compressed_size;
	ret = __send(sk, send_buf, total_len, 0);
	if (ret != total_len) {
		pr_perror("Failed to send compressed page (sent %d/%d)", ret, total_len);
		return -1;
	}

	return 0;
}

static __maybe_unused int send_page_uncompressed(int sk, const void *data,
						 u64 dst_id,
						 unsigned long vaddr)
{
	char send_buf[sizeof(struct page_server_iov) + PAGE_SIZE];
	struct page_server_iov *pi = (struct page_server_iov *)send_buf;
	void *payload = send_buf + sizeof(*pi);
	int total_len;
	int ret;

	memcpy(payload, data, PAGE_SIZE);

	pi->cmd = encode_ps_cmd(PS_IOV_ADD_F, PE_PRESENT);
	pi->nr_pages = 1;
	pi->vaddr = vaddr;
	pi->dst_id = dst_id;

	total_len = sizeof(*pi) + PAGE_SIZE;
	ret = __send(sk, send_buf, total_len, 0);
	if (ret != total_len) {
		pr_perror("Failed to send page (sent %d/%d)", ret, total_len);
		return -1;
	}

	return 0;
}

static void tcp_cork(int sk, bool on)
{
	int val = on ? 1 : 0;
	if (setsockopt(sk, SOL_TCP, TCP_CORK, &val, sizeof(val)))
		pr_pwarn("Unable to set TCP_CORK=%d", val);
}

static void tcp_nodelay(int sk, bool on)
{
	int val = on ? 1 : 0;
	if (setsockopt(sk, SOL_TCP, TCP_NODELAY, &val, sizeof(val)))
		pr_pwarn("Unable to set TCP_NODELAY=%d", val);
}

/* page-server xfer */
static int write_pages_to_server(struct page_xfer *xfer, int p, unsigned long len)
{
	ssize_t ret, left = len;

	if (opts.tls) {
		pr_debug("Sending %lx bytes\n", len);

		if (tls_send_data_from_fd(p, len))
			return -1;
	} else {
		pr_debug("Splicing %lx bytes into socket\n", len);

		while (left > 0) {
			ret = splice(p, NULL, xfer->sk, NULL, left, SPLICE_F_MOVE);
			if (ret < 0) {
				pr_perror("Can't write pages to socket");
				return -1;
			}

			pr_debug("\tSpliced: %lx bytes sent\n", (unsigned long)ret);
			left -= ret;
		}
	}

	return 0;
}

static int write_pagemap_to_server(struct page_xfer *xfer, struct iovec *iov, u32 flags)
{
	struct page_server_iov pi = {
		.cmd = encode_ps_cmd(PS_IOV_ADD_F, flags),
		.nr_pages = iov->iov_len / PAGE_SIZE,
		.vaddr = encode_pointer(iov->iov_base),
		.dst_id = xfer->dst_id,
	};

	return send_psi(xfer->sk, &pi);
}

static void close_server_xfer(struct page_xfer *xfer)
{
	xfer->sk = -1;
}

static int open_page_server_xfer(struct page_xfer *xfer, int fd_type, unsigned long img_id)
{
	char has_parent;
	struct page_server_iov pi = {
		.cmd = PS_IOV_OPEN2,
	};

	xfer->sk = page_server_sk;
	xfer->write_pagemap = write_pagemap_to_server;
	xfer->write_pages = write_pages_to_server;
	xfer->close = close_server_xfer;
	xfer->dst_id = encode_pm(fd_type, img_id);
	xfer->parent = NULL;

	pi.dst_id = xfer->dst_id;
	if (send_psi(xfer->sk, &pi)) {
		pr_perror("Can't write to page server");
		return -1;
	}

	/* Push the command NOW */
	tcp_nodelay(xfer->sk, true);

	if (__recv(xfer->sk, &has_parent, 1, 0) != 1) {
		pr_perror("The page server doesn't answer");
		return -1;
	}

	if (has_parent)
		xfer->parent = (void *)1; /* This is required for generate_iovs() */

	return 0;
}

/* local xfer */
static int write_pages_loc(struct page_xfer *xfer, int p, unsigned long len)
{
	ssize_t ret;
	ssize_t curr = 0;

	while (1) {
		ret = splice(p, NULL, img_raw_fd(xfer->pi), NULL, len - curr, SPLICE_F_MOVE);
		if (ret == -1) {
			pr_perror("Unable to spice data");
			return -1;
		}
		if (ret == 0) {
			pr_err("A pipe was closed unexpectedly\n");
			return -1;
		}
		curr += ret;
		if (curr == len)
			break;
	}

	return 0;
}

static int check_pagehole_in_parent(struct page_read *p, struct iovec *iov)
{
	int ret;
	unsigned long off, end;

	/*
	 * Try to find pagemap entry in parent, from which
	 * the data will be read on restore.
	 *
	 * This is the optimized version of the page-by-page
	 * read_pagemap_page routine.
	 */

	pr_debug("Checking %p - %p hole\n", iov->iov_base, iov->iov_base + iov->iov_len);
	off = (unsigned long)iov->iov_base;
	end = off + iov->iov_len;
	while (1) {
		unsigned long pend;

		ret = p->seek_pagemap(p, off);
		if (ret <= 0 || !p->pe) {
			pr_err("Missing %lx in parent pagemap\n", off);
			return -1;
		}

		pr_debug("\tFound %" PRIx64 " - %" PRIx64 "\n",
			 p->pe->vaddr, p->pe->vaddr + pagemap_len(p->pe));

		/*
		 * The pagemap entry in parent may happen to be
		 * shorter, than the hole we write. In this case
		 * we should go ahead and check the remainder.
		 */

		pend = p->pe->vaddr + pagemap_len(p->pe);
		if (end <= pend)
			return 0;

		pr_debug("\t\tcontinue on %lx\n", pend);
		off = pend;
	}
}

static int write_pagemap_loc(struct page_xfer *xfer, struct iovec *iov, u32 flags)
{
	int ret;
	PagemapEntry pe = PAGEMAP_ENTRY__INIT;

	pe.vaddr = encode_pointer(iov->iov_base);
	pe.nr_pages = iov->iov_len / PAGE_SIZE;
	pe.has_flags = true;
	pe.flags = flags;
	pe.has_nr_pages = true;

	if (flags & PE_PRESENT) {
		if (opts.auto_dedup && xfer->parent != NULL) {
			ret = dedup_one_iovec(xfer->parent, pe.vaddr, pagemap_len(&pe));
			if (ret == -1) {
				pr_perror("Auto-deduplication failed");
				return ret;
			}
		}
	} else if (flags & PE_PARENT) {
		if (xfer->parent != NULL) {
			ret = check_pagehole_in_parent(xfer->parent, iov);
			if (ret) {
				pr_err("Hole %p - %p not found in parent\n",
				       iov->iov_base, iov->iov_base + iov->iov_len);
				return -1;
			}
		}
	}

	if (pb_write_one(xfer->pmi, &pe, PB_PAGEMAP) < 0)
		return -1;

	return 0;
}

static void close_page_xfer(struct page_xfer *xfer)
{
	if (xfer->parent != NULL) {
		xfer->parent->close(xfer->parent);
		xfree(xfer->parent);
		xfer->parent = NULL;
	}
	close_image(xfer->pi);
	close_image(xfer->pmi);
}

static int open_page_local_xfer(struct page_xfer *xfer, int fd_type, unsigned long img_id)
{
	u32 pages_id;

	xfer->pmi = open_image(fd_type, O_DUMP, img_id);
	if (!xfer->pmi)
		return -1;

	xfer->pi = open_pages_image(O_DUMP, xfer->pmi, &pages_id);
	if (!xfer->pi)
		goto err_pmi;

	/*
	 * Open page-read for parent images (if it exists). It will
	 * be used for two things:
	 * 1) when writing a page, those from parent will be dedup-ed
	 * 2) when writing a hole, the respective place would be checked
	 *    to exist in parent (either pagemap or hole)
	 */
	xfer->parent = NULL;
	if (fd_type == CR_FD_PAGEMAP || fd_type == CR_FD_SHMEM_PAGEMAP) {
		int ret;
		int pfd;
		int pr_flags = (fd_type == CR_FD_PAGEMAP) ? PR_TASK : PR_SHMEM;

		/* Image streaming lacks support for incremental images */
		if (opts.stream)
			goto out;

		if (open_parent(get_service_fd(IMG_FD_OFF), &pfd))
			goto err_pi;
		if (pfd < 0)
			goto out;

		xfer->parent = xmalloc(sizeof(*xfer->parent));
		if (!xfer->parent) {
			close(pfd);
			goto err_pi;
		}

		ret = open_page_read_at(pfd, img_id, xfer->parent, pr_flags);
		if (ret <= 0) {
			pr_perror("No parent image found, though parent directory is set");
			xfree(xfer->parent);
			xfer->parent = NULL;
			close(pfd);
			goto out;
		}
		close(pfd);
	}

out:
	xfer->write_pagemap = write_pagemap_loc;
	xfer->write_pages = write_pages_loc;
	xfer->close = close_page_xfer;
	return 0;

err_pi:
	close_image(xfer->pi);
err_pmi:
	close_image(xfer->pmi);
	return -1;
}

int open_page_xfer(struct page_xfer *xfer, int fd_type, unsigned long img_id)
{
	xfer->offset = 0;
	xfer->transfer_lazy = true;

	if (opts.use_page_server)
		return open_page_server_xfer(xfer, fd_type, img_id);
	else
		return open_page_local_xfer(xfer, fd_type, img_id);
}

static int page_xfer_dump_hole(struct page_xfer *xfer, struct iovec *hole, u32 flags)
{
	BUG_ON(hole->iov_base < (void *)xfer->offset);
	hole->iov_base -= xfer->offset;
	pr_debug("\th %p [%u]\n", hole->iov_base, (unsigned int)(hole->iov_len / PAGE_SIZE));

		pr_info("  Writing hole pagemap asaf: 0x%lx-0x%lx (%lu pages)\n",
						(unsigned long)hole->iov_base, (unsigned long)(hole->iov_base+hole->iov_len), (unsigned long)(hole->iov_len/PAGE_SIZE));
	if (xfer->write_pagemap(xfer, hole, flags))
		return -1;

	return 0;
}

static int get_hole_flags(struct page_pipe *pp, int n)
{
	unsigned int hole_flags = pp->hole_flags[n];

	if (hole_flags == PP_HOLE_PARENT)
		return PE_PARENT;
	else
		BUG();

	return -1;
}

static int dump_holes(struct page_xfer *xfer, struct page_pipe *pp, unsigned int *cur_hole, void *limit)
{
	int ret;

	for (; *cur_hole < pp->free_hole; (*cur_hole)++) {
		struct iovec hole = pp->holes[*cur_hole];
		u32 hole_flags;

		if (limit && hole.iov_base >= limit)
			break;

		hole_flags = get_hole_flags(pp, *cur_hole);
		ret = page_xfer_dump_hole(xfer, &hole, hole_flags);
		if (ret)
			return ret;
	}

	return 0;
}

static inline u32 ppb_xfer_flags(struct page_xfer *xfer, struct page_pipe_buf *ppb)
{
	if (ppb->flags & PPB_LAZY)
		/*
		 * Pages that can be lazily restored are always marked as such.
		 * In the case we actually transfer them into image mark them
		 * as present as well.
		 */
		return (xfer->transfer_lazy ? PE_PRESENT : 0) | PE_LAZY;
	else
		return PE_PRESENT;
}

/*
 * Optimized pre-dump algorithm
 * ==============================
 *
 * Note: Please refer man(2) page of process_vm_readv syscall.
 *
 * The following discussion covers the possibly faulty-iov
 * locations in an iovec, which hinders process_vm_readv from
 * dumping the entire iovec in a single invocation.
 *
 * Memory layout of target process:
 *
 * Pages: A        B        C
 *	  +--------+--------+--------+--------+--------+--------+
 *	  |||||||||||||||||||||||||||||||||||||||||||||||||||||||
 *	  +--------+--------+--------+--------+--------+--------+
 *
 * Single "iov" representation: {starting_address, length_in_bytes}
 * An iovec is array of iov-s.
 *
 * NOTE: For easy representation and discussion purpose, we carry
 *	 out further discussion at "page granularity".
 *	 length_in_bytes will represent page count in iov instead
 *	 of byte count. Same assumption applies for the syscall's
 *	 return value. Instead of returning the number of bytes
 *	 read, it returns a page count.
 *
 * For above memory mapping, generated iovec: {A,1}{B,1}{C,4}
 *
 * This iovec remains unmodified once generated. At the same
 * time some of memory regions listed in iovec may get modified
 * (unmap/change protection) by the target process while syscall
 * is trying to dump iovec regions.
 *
 * Case 1:
 *	A is unmapped, {A,1} become faulty iov
 *
 *      A        B        C
 *      +--------+--------+--------+--------+--------+--------+
 *      |        ||||||||||||||||||||||||||||||||||||||||||||||
 *      +--------+--------+--------+--------+--------+--------+
 *      ^        ^
 *      |        |
 *      start    |
 *      (1)      |
 *               start
 *               (2)
 *
 *	process_vm_readv will return -1. Increment start pointer(2),
 *	syscall will process {B,1}{C,4} in one go and copy 5 pages
 *	to userbuf from iov-B and iov-C.
 *
 * Case 2:
 *	B is unmapped, {B,1} become faulty iov
 *
 *      A        B        C
 *      +--------+--------+--------+--------+--------+--------+
 *      |||||||||         |||||||||||||||||||||||||||||||||||||
 *      +--------+--------+--------+--------+--------+--------+
 *      ^                 ^
 *      |                 |
 *      start             |
 *      (1)               |
 *                        start
 *                        (2)
 *
 *	process_vm_readv will return 1, i.e. page A copied to
 *	userbuf successfully and syscall stopped, since B got
 *	unmapped.
 *
 *	Increment the start pointer to C(2) and invoke syscall.
 *	Userbuf contains 5 pages overall from iov-A and iov-C.
 *
 * Case 3:
 *	This case deals with partial unmapping of iov representing
 *	more than one pagesize region.
 *
 *	Syscall can't process such faulty iov as whole. So we
 *	process such regions part-by-part and form new sub-iovs
 *	in aux_iov from successfully processed pages.
 *
 *
 *	Part 3.1:
 *		First page of C is unmapped
 *
 *      A        B        C
 *      +--------+--------+--------+--------+--------+--------+
 *      ||||||||||||||||||         ||||||||||||||||||||||||||||
 *      +--------+--------+--------+--------+--------+--------+
 *      ^                          ^
 *      |                          |
 *      start                      |
 *      (1)                        |
 *                                 dummy
 *                                 (2)
 *
 *	process_vm_readv will return 2, i.e. pages A and B copied.
 *	We identify length of iov-C is more than 1 page, that is
 *	where this case differs from Case 2.
 *
 *	dummy-iov is introduced(2) as: {C+1,3}. dummy-iov can be
 *	directly placed at next page to failing page. This will copy
 *	remaining 3 pages from iov-C to userbuf. Finally create
 *	modified iov entry in aux_iov. Complete aux_iov look like:
 *
 *	aux_iov: {A,1}{B,1}{C+1,3}*
 *
 *
 *	Part 3.2:
 *		In between page of C is unmapped, let's say third
 *
 *      A        B        C
 *      +--------+--------+--------+--------+--------+--------+
 *      ||||||||||||||||||||||||||||||||||||         ||||||||||
 *      +--------+--------+--------+--------+--------+--------+
 *      ^                                            ^
 *      |                 |-----------------|        |
 *      start              partial_read_bytes        |
 *      (1)                                          |
 *                                                   dummy
 *                                                   (2)
 *
 *	process_vm_readv will return 4, i.e. pages A and B copied
 *	completely and first two pages of C are also copied.
 *
 *	Since, iov-C is not processed completely, we need to find
 *	"partial_read_byte" count to place out dummy-iov for
 *	remaining processing of iov-C. This function is performed by
 *	analyze_iov function.
 *
 *	dummy-iov will be(2): {C+3,1}. dummy-iov will be placed
 *	next to first failing address to process remaining iov-C.
 *	New entries in aux_iov will look like:
 *
 *	aux_iov: {A,1}{B,1}{C,2}*{C+3,1}*
 */

unsigned long handle_faulty_iov(int pid, struct iovec *riov, unsigned long faulty_index, struct iovec *bufvec,
				struct iovec *aux_iov, unsigned long *aux_len)
{
	struct iovec dummy;
	ssize_t bytes_read;
	unsigned long final_read_cnt = 0;

	/* Handling Case 3-Part 3.2*/
	dummy.iov_base = riov[faulty_index].iov_base;
	dummy.iov_len = riov[faulty_index].iov_len;

	while (dummy.iov_len) {
		bytes_read = process_vm_readv(pid, bufvec, 1, &dummy, 1, 0);
		if (bytes_read == -1) {
			/* Handling faulty page read in faulty iov */
			cnt_sub(CNT_PAGES_WRITTEN, 1);
			dummy.iov_base += PAGE_SIZE;
			dummy.iov_len -= PAGE_SIZE;
			continue;
		}

		/* If aux-iov can merge and expand or new entry required */
		if (aux_iov[(*aux_len) - 1].iov_base + aux_iov[(*aux_len) - 1].iov_len == dummy.iov_base)
			aux_iov[(*aux_len) - 1].iov_len += bytes_read;
		else {
			aux_iov[*aux_len].iov_base = dummy.iov_base;
			aux_iov[*aux_len].iov_len = bytes_read;
			(*aux_len) += 1;
		}

		dummy.iov_base += bytes_read;
		dummy.iov_len -= bytes_read;
		bufvec->iov_base += bytes_read;
		bufvec->iov_len -= bytes_read;
		final_read_cnt += bytes_read;
	}

	return final_read_cnt;
}

/*
 * This function will position start pointer to the latest
 * successfully read iov in iovec.
 */
static unsigned long analyze_iov(ssize_t bytes_read, struct iovec *riov, unsigned long *index, struct iovec *aux_iov,
				 unsigned long *aux_len)
{
	ssize_t processed_bytes = 0;

	/* correlating iovs with read bytes */
	while (processed_bytes < bytes_read) {
		processed_bytes += riov[*index].iov_len;
		aux_iov[*aux_len].iov_base = riov[*index].iov_base;
		aux_iov[*aux_len].iov_len = riov[*index].iov_len;

		(*aux_len) += 1;
		(*index) += 1;
	}

	/* handling partially processed faulty iov*/
	if (processed_bytes - bytes_read) {
		unsigned long partial_read_bytes = 0;

		(*index) -= 1;

		partial_read_bytes = riov[*index].iov_len - (processed_bytes - bytes_read);
		aux_iov[*aux_len - 1].iov_len = partial_read_bytes;
		riov[*index].iov_base += partial_read_bytes;
		riov[*index].iov_len -= partial_read_bytes;
	}

	return 0;
}

/*
 * This function iterates over complete ppb->iov entries and pass
 * them to process_vm_readv syscall.
 *
 * Since process_vm_readv returns count of successfully read bytes.
 * It does not point to iovec entry associated to last successful
 * byte read. The correlation between bytes read and corresponding
 * iovec is setup through analyze_iov function.
 *
 * If all iovecs are not processed in one go, it means there exists
 * some faulty iov entry(memory mapping modified after it was grabbed)
 * in iovec. process_vm_readv syscall stops at such faulty iov and
 * skip processing further any entry in iovec. This is handled by
 * handle_faulty_iov function.
 */
static long fill_userbuf(int pid, struct page_pipe_buf *ppb, struct iovec *bufvec, struct iovec *aux_iov,
			 unsigned long *aux_len)
{
	struct iovec *riov = ppb->iov;
	ssize_t bytes_read;
	unsigned long total_read = 0;
	unsigned long start = 0;

	while (start < ppb->nr_segs) {
		bytes_read = process_vm_readv(pid, bufvec, 1, &riov[start], ppb->nr_segs - start, 0);
		if (bytes_read == -1) {
			if (errno == ESRCH) {
				pr_debug("Target process PID:%d not found\n", pid);
				return -ESRCH;
			}
			if (errno != EFAULT) {
				pr_perror("process_vm_readv failed");
				return -1;
			}
			/* Handling Case 1*/
			if (riov[start].iov_len == PAGE_SIZE) {
				cnt_sub(CNT_PAGES_WRITTEN, 1);
				start += 1;
				continue;
			}
			total_read += handle_faulty_iov(pid, riov, start, bufvec, aux_iov, aux_len);
			start += 1;
			continue;
		}

		if (bytes_read > 0) {
			if (analyze_iov(bytes_read, riov, &start, aux_iov, aux_len) < 0)
				return -1;
			bufvec->iov_base += bytes_read;
			bufvec->iov_len -= bytes_read;
			total_read += bytes_read;
		}
	}

	return total_read;
}

/*
 * This function is similar to page_xfer_dump_pages, instead it uses
 * auxiliary_iov array for pagemap generation.
 *
 * The entries of ppb->iov may mismatch with actual process mappings
 * present at time of pre-dump. Such entries need to be adjusted as per
 * the pages read by process_vm_readv syscall. These adjusted entries
 * along with unmodified entries are present in aux_iov array.
 */

int page_xfer_predump_pages(int pid, struct page_xfer *xfer, struct page_pipe *pp)
{
	struct page_pipe_buf *ppb;
	unsigned int cur_hole = 0, i;
	unsigned long ret, bytes_read;
	unsigned long userbuf_len;
	struct iovec bufvec;

	struct iovec *aux_iov;
	unsigned long aux_len;
	void *userbuf;

	userbuf_len = PIPE_MAX_BUFFER_SIZE;
	userbuf = mmap(NULL, userbuf_len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (userbuf == MAP_FAILED) {
		pr_perror("Unable to mmap a buffer");
		return -1;
	}
	aux_iov = xmalloc(userbuf_len / PAGE_SIZE * sizeof(aux_iov[0]));
	if (!aux_iov)
		goto err;

	list_for_each_entry(ppb, &pp->bufs, l) {
		if (ppb->pipe_size * PAGE_SIZE > userbuf_len) {
			void *addr;

			addr = mremap(userbuf, userbuf_len, ppb->pipe_size * PAGE_SIZE, MREMAP_MAYMOVE);
			if (addr == MAP_FAILED) {
				pr_perror("Unable to mmap a buffer");
				goto err;
			}
			userbuf_len = ppb->pipe_size * PAGE_SIZE;
			userbuf = addr;
			addr = xrealloc(aux_iov, ppb->pipe_size * sizeof(aux_iov[0]));
			if (!addr)
				goto err;
			aux_iov = addr;
		}
		timing_start(TIME_MEMDUMP);

		aux_len = 0;
		bufvec.iov_len = userbuf_len;
		bufvec.iov_base = userbuf;

		bytes_read = fill_userbuf(pid, ppb, &bufvec, aux_iov, &aux_len);
		if (bytes_read == -ESRCH) {
			timing_stop(TIME_MEMDUMP);
			munmap(userbuf, userbuf_len);
			xfree(aux_iov);
			return 0;
		}
		if (bytes_read < 0)
			goto err;

		bufvec.iov_base = userbuf;
		bufvec.iov_len = bytes_read;
		ret = vmsplice(ppb->p[1], &bufvec, 1, SPLICE_F_NONBLOCK | SPLICE_F_GIFT);

		if (ret == -1 || ret != bytes_read) {
			pr_err("vmsplice: Failed to splice user buffer to pipe %ld\n", ret);
			goto err;
		}

		timing_stop(TIME_MEMDUMP);
		timing_start(TIME_MEMWRITE);

		/* generating pagemap */
		for (i = 0; i < aux_len; i++) {
			struct iovec iov = aux_iov[i];
			u32 flags;

			ret = dump_holes(xfer, pp, &cur_hole, iov.iov_base);
			if (ret)
				goto err;

			BUG_ON(iov.iov_base < (void *)xfer->offset);
			iov.iov_base -= xfer->offset;
			pr_debug("\t p %p - %p\n", iov.iov_base, iov.iov_base + iov.iov_len);

			flags = ppb_xfer_flags(xfer, ppb);

			if (xfer->write_pagemap(xfer, &iov, flags))
				goto err;

			if (xfer->write_pages(xfer, ppb->p[0], iov.iov_len))
				goto err;
		}

		timing_stop(TIME_MEMWRITE);
	}

	munmap(userbuf, userbuf_len);
	xfree(aux_iov);
	timing_start(TIME_MEMWRITE);

	return dump_holes(xfer, pp, &cur_hole, NULL);
err:
	munmap(userbuf, userbuf_len);
	xfree(aux_iov);
	return -1;
}

/* Helper to write lazy VMA pagemap entries that come before a given vaddr */
static int write_lazy_vmas_before(struct page_xfer *xfer, unsigned long before_vaddr,
				   struct lazy_vma_entry **cur_lve)
{
	struct list_head *global_list = get_global_lazy_vmas();
	struct lazy_vma_entry *lve = *cur_lve;

	/* Start from beginning if not set */
	if (!lve && !list_empty(global_list))
		lve = list_first_entry(global_list, struct lazy_vma_entry, list);

	/* Write all lazy VMAs that start before before_vaddr.
	 * Use lve->start/end (not lve->vma->e) since vma structs
	 * may be freed after the dump completes.
	 */
	while (lve && &lve->list != global_list) {
		struct iovec iov;
		u32 flags = PE_LAZY;
		unsigned long vma_start = lve->start;

		/*
		 * In server mode, filter VMAs by dst_id (for multi-process dumps).
		 * In local mode, xfer->dst_id is unreliable (union with pmi/pi),
		 * so skip the check. COW local mode dumps single process anyway.
		 */
		if (opts.use_page_server && lve->dst_id != xfer->dst_id) {
			lve = list_entry(lve->list.next, struct lazy_vma_entry, list);
			continue;
		}

		/* Stop if this VMA starts at or after our limit */
		if (vma_start >= before_vaddr)
			break;

		iov.iov_base = (void *)(unsigned long)lve->start;
		iov.iov_len = lve->end - lve->start;

		BUG_ON(iov.iov_base < (void *)xfer->offset);
		iov.iov_base -= xfer->offset;

		pr_debug("Writing lazy VMA pagemap: 0x%lx-0x%lx (%lu pages)\n",
			(unsigned long)lve->start, (unsigned long)lve->end,
			(unsigned long)(iov.iov_len / PAGE_SIZE));

		if (xfer->write_pagemap(xfer, &iov, flags)) {
			pr_err("Failed to write pagemap for lazy VMA\n");
			return -1;
		}

		lve = list_entry(lve->list.next, struct lazy_vma_entry, list);
	}

	*cur_lve = lve;
	return 0;
}

int page_xfer_dump_pages(struct page_xfer *xfer, struct page_pipe *pp)
{
	struct page_pipe_buf *ppb;
	unsigned int cur_hole = 0;
	struct lazy_vma_entry *cur_lve = NULL;
	int ret;

	pr_debug("Transferring pages:\n");
	

	/* In COW dump mode, we need to interleave lazy VMA entries with pipe entries */
	if (opts.cow_dump) {
		pr_info("Writing pagemap entries (interleaved mode) for dst_id=%lu\n", 
			(unsigned long)xfer->dst_id);
	}

	list_for_each_entry(ppb, &pp->bufs, l) {
		unsigned int i;

		pr_debug("\tbuf %lx/%d\n", ppb->pages_in, ppb->nr_segs);

		for (i = 0; i < ppb->nr_segs; i++) {
			struct iovec iov = ppb->iov[i];
			u32 flags;
			unsigned long seg_vaddr = (unsigned long)iov.iov_base + xfer->offset;
			

			ret = dump_holes(xfer, pp, &cur_hole, iov.iov_base);
			if (ret)
				return ret;

			/* Write any lazy VMAs that should come before this segment */
			if (opts.cow_dump) {
				ret = write_lazy_vmas_before(xfer, seg_vaddr, &cur_lve);
				if (ret)
					return ret;
			}

			BUG_ON(iov.iov_base < (void *)xfer->offset);
			iov.iov_base -= xfer->offset;
			pr_debug("\tp %p - %p\n", iov.iov_base, iov.iov_base + iov.iov_len);

			flags = ppb_xfer_flags(xfer, ppb);
			

			pr_debug("Writing pagemap segment: 0x%lx-0x%lx (%lu pages)\n",
				 (unsigned long)iov.iov_base, (unsigned long)(iov.iov_base + iov.iov_len),
				 (unsigned long)(iov.iov_len / PAGE_SIZE));

			if (xfer->write_pagemap(xfer, &iov, flags))
				return -1;
			if ((flags & PE_PRESENT) && xfer->write_pages(xfer, ppb->p[0], iov.iov_len))
				return -1;
			

		}
	}
	

	ret = dump_holes(xfer, pp, &cur_hole, NULL);
	if (ret)
		return ret;

	/* Write any remaining lazy VMAs after all pipe entries */
	if (opts.cow_dump) {
		ret = write_lazy_vmas_before(xfer, ULONG_MAX, &cur_lve);
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * Return:
 *	 1 - if a parent image exists
 *	 0 - if a parent image doesn't exist
 *	-1 - in error cases
 */
int check_parent_local_xfer(int fd_type, unsigned long img_id)
{
	char path[PATH_MAX];
	struct stat st;
	int ret, pfd;

	/* Image streaming lacks support for incremental images */
	if (opts.stream)
		return 0;

	if (open_parent(get_service_fd(IMG_FD_OFF), &pfd))
		return -1;
	if (pfd < 0)
		return 0;

	snprintf(path, sizeof(path), imgset_template[fd_type].fmt, img_id);
	ret = fstatat(pfd, path, &st, 0);
	if (ret == -1 && errno != ENOENT) {
		pr_perror("Unable to stat %s", path);
		close(pfd);
		return -1;
	}

	close(pfd);
	return (ret == 0);
}

/* page server */
static int page_server_check_parent(int sk, struct page_server_iov *pi)
{
	int type, ret;
	unsigned long id;

	type = decode_pm(pi->dst_id, &id);
	if (type == -1) {
		pr_err("Unknown pagemap type received\n");
		return -1;
	}

	ret = check_parent_local_xfer(type, id);
	if (ret < 0)
		return -1;

	if (__send(sk, &ret, sizeof(ret), 0) != sizeof(ret)) {
		pr_perror("Unable to send response");
		return -1;
	}

	return 0;
}

static int check_parent_server_xfer(int fd_type, unsigned long img_id)
{
	struct page_server_iov pi = {};
	int has_parent;

	pi.cmd = PS_IOV_PARENT;
	pi.dst_id = encode_pm(fd_type, img_id);

	if (send_psi(page_server_sk, &pi))
		return -1;

	tcp_nodelay(page_server_sk, true);

	if (__recv(page_server_sk, &has_parent, sizeof(int), 0) != sizeof(int)) {
		pr_perror("The page server doesn't answer");
		return -1;
	}

	return has_parent;
}

int check_parent_page_xfer(int fd_type, unsigned long img_id)
{
	if (opts.use_page_server)
		return check_parent_server_xfer(fd_type, img_id);
	else
		return check_parent_local_xfer(fd_type, img_id);
}

struct page_xfer_job {
	u64 dst_id;
	int p[2];
	unsigned pipe_size;
	struct page_xfer loc_xfer;
};

static struct page_xfer_job cxfer = {
	.dst_id = ~0,
};

static struct pipe_read_dest pipe_read_dest = {
	.sink_fd = -1,
};

static void page_server_close(void)
{
	if (cxfer.dst_id != ~0)
		cxfer.loc_xfer.close(&cxfer.loc_xfer);
	if (pipe_read_dest.sink_fd != -1) {
		close(pipe_read_dest.sink_fd);
		close(pipe_read_dest.p[0]);
		close(pipe_read_dest.p[1]);
	}
}

static int page_server_open(int sk, struct page_server_iov *pi)
{
	int type;
	unsigned long id;

	type = decode_pm(pi->dst_id, &id);
	if (type == -1) {
		pr_err("Unknown pagemap type received\n");
		return -1;
	}

	pr_info("Opening %d/%lu\n", type, id);

	page_server_close();

	if (open_page_local_xfer(&cxfer.loc_xfer, type, id))
		return -1;

	cxfer.dst_id = pi->dst_id;

	if (sk >= 0) {
		char has_parent = !!cxfer.loc_xfer.parent;
		if (__send(sk, &has_parent, 1, 0) != 1) {
			pr_perror("Unable to send response");
			close_page_xfer(&cxfer.loc_xfer);
			return -1;
		}
	}

	return 0;
}

static int prep_loc_xfer(struct page_server_iov *pi)
{
	if (cxfer.dst_id != pi->dst_id) {
		pr_warn("Deprecated IO w/o open\n");
		return page_server_open(-1, pi);
	} else
		return 0;
}

/* Statistics tracking structure */
static struct {
	/* page_server_get_pages counters */
	unsigned long get_total_requests;
	unsigned long get_with_cow;
	unsigned long get_no_cow;
	unsigned long get_total_pages;
	unsigned long get_cow_pages;
	unsigned long get_errors;
	
	/* page_server_serve counters */
	unsigned long serve_open;
	unsigned long serve_open2;
	unsigned long serve_parent;
	unsigned long serve_add_f;
	unsigned long serve_add;
	unsigned long serve_hole;
	unsigned long serve_close;
	unsigned long serve_force_close;
	unsigned long serve_get;
	unsigned long serve_unknown;
	
	time_t last_print_time;
} ps_stats;

static void check_and_print_stats(void)
{
	time_t now = time(NULL);

	if (now - ps_stats.last_print_time >= 1) {
		pr_debug("[PAGE_SERVER_STATS] get_pages: reqs=%lu with_cow=%lu no_cow=%lu pages=%lu cow=%lu errs=%lu | serve: open2=%lu parent=%lu add_f=%lu get=%lu close=%lu\n",
			ps_stats.get_total_requests,
			ps_stats.get_with_cow,
			ps_stats.get_no_cow,
			ps_stats.get_total_pages,
			ps_stats.get_cow_pages,
			ps_stats.get_errors,
			ps_stats.serve_open2,
			ps_stats.serve_parent,
			ps_stats.serve_add_f,
			ps_stats.serve_get,
			ps_stats.serve_close + ps_stats.serve_force_close);
		
		/* Reset all counters */
		memset(&ps_stats, 0, sizeof(ps_stats));
		ps_stats.last_print_time = now;
	}
}

static int page_server_add(int sk, struct page_server_iov *pi, u32 flags, bool compressed)
{
	size_t len;
	struct page_xfer *lxfer = &cxfer.loc_xfer;
	struct iovec iov;

	pr_debug("Adding %" PRIx64 " - %" PRIx64 " (compressed=%d)\n",
		 pi->vaddr, pi->vaddr + pi->nr_pages * PAGE_SIZE, compressed);

	if (prep_loc_xfer(pi))
		return -1;

	psi2iovec(pi, &iov);
	if (lxfer->write_pagemap(lxfer, &iov, flags))
		return -1;

	if (!(flags & PE_PRESENT))
		return 0;

	/* Handle compressed data - receive, decompress, write page by page */
	if (compressed) {
		unsigned long pages_left = pi->nr_pages;
		
		while (pages_left > 0) {
			int compressed_size;
			char compressed_buf[LZ4_compressBound(PAGE_SIZE)];
			char decompressed[PAGE_SIZE];
			int decomp_ret;

			/* Receive compressed size */
			if (__recv(sk, &compressed_size, sizeof(compressed_size), MSG_WAITALL) != sizeof(compressed_size)) {
				pr_perror("Failed to receive compressed size");
				return -1;
			}

			if (compressed_size <= 0 || compressed_size > LZ4_compressBound(PAGE_SIZE)) {
				pr_err("Invalid compressed size: %d\n", compressed_size);
				return -1;
			}

			/* Receive compressed data */
			if (__recv(sk, compressed_buf, compressed_size, MSG_WAITALL) != compressed_size) {
				pr_perror("Failed to receive compressed data");
				return -1;
			}

			/* Decompress */
			decomp_ret = LZ4_decompress_safe(compressed_buf, decompressed, compressed_size, PAGE_SIZE);
			if (decomp_ret != PAGE_SIZE) {
				pr_err("LZ4 decompression failed: expected %lu, got %d\n", PAGE_SIZE, decomp_ret);
				return -1;
			}

			pr_debug("Decompressed page: %d -> %lu bytes\n", compressed_size, PAGE_SIZE);

			/* Write decompressed page data to pipe and then to image */
			if (write(cxfer.p[1], decompressed, PAGE_SIZE) != PAGE_SIZE) {
				pr_perror("Failed to write decompressed page to pipe");
				return -1;
			}

			if (lxfer->write_pages(lxfer, cxfer.p[0], PAGE_SIZE))
				return -1;

			pages_left--;
		}
		return 0;
	}

	/* Handle uncompressed data - original splice-based path */
	len = iov.iov_len;
	while (len > 0) {
		ssize_t chunk;

		chunk = len;
		if (chunk > cxfer.pipe_size)
			chunk = cxfer.pipe_size;

		/*
		 * Splicing into a pipe may end up blocking if pipe is "full",
		 * and we need the SPLICE_F_NONBLOCK flag here. At the same time
		 * splicing from UNIX socket with this flag aborts splice with
		 * the EAGAIN if there's no data in it (TCP looks at the socket
		 * O_NONBLOCK flag _only_ and waits for data), so before doing
		 * the non-blocking splice we need to explicitly wait.
		 */

		if (sk_wait_data(sk) < 0) {
			pr_perror("Can't poll socket");
			return -1;
		}

		if (opts.tls) {
			if (tls_recv_data_to_fd(cxfer.p[1], chunk)) {
				pr_err("Can't read from socket\n");
				return -1;
			}
		} else {
			chunk = splice(sk, NULL, cxfer.p[1], NULL, chunk, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

			if (chunk < 0) {
				pr_perror("Can't read from socket");
				return -1;
			}
			if (chunk == 0) {
				pr_err("A socket was closed unexpectedly\n");
				return -1;
			}
		}

		if (lxfer->write_pages(lxfer, cxfer.p[0], chunk))
			return -1;

		len -= chunk;
	}

	return 0;
}

/* Chunk size for batch transfer: 4KB = 1 page (to avoid COW race conditions) */
#define BATCH_CHUNK_SIZE (1)

/* Page request queue for PS_IOV_GET requests */
struct page_request_entry {
	unsigned long vaddr;
	unsigned long nr_pages;
	int sk;
	u64 dst_id;

	/* Location info (filled on first access) */
	struct page_pipe_buf *ppb;
	unsigned int seg_idx;
	unsigned long page_idx_in_seg;
	bool location_found;  /* Flag: have we looked up location yet? */
};

/* SPSC queue node type for page request entries */
DECLARE_SPSC_NODE(page_request, struct page_request_entry);

/* SPSC queue with cache-line padding to prevent false sharing */
static struct page_request_spsc_node *page_request_head;  /* Consumer (Thread 3) */
static char _page_req_pad[128 - sizeof(struct page_request_spsc_node *)] __attribute__((unused));
static struct page_request_spsc_node *page_request_tail;  /* Producer (Thread 2) */
static unsigned long page_request_queue_size;  /* Atomic counter */
static bool page_request_queue_initialized = false;

static void init_page_request_queue(void)
{
	if (page_request_queue_initialized)
		return;

	if (spsc_init(page_request_head, page_request_tail,
		      page_request_queue_size,
		      struct page_request_spsc_node)) {
		pr_err("Failed to allocate dummy node for page request queue\n");
		return;
	}

	page_request_queue_initialized = true;
}

/* Lock-free SPSC enqueue (Thread 2 produces page requests) */
static void add_page_request(unsigned long vaddr, unsigned long nr_pages, int sk, u64 dst_id)
{
	struct page_request_entry *entry;

	entry = xmalloc(sizeof(*entry));
	if (!entry) {
		pr_err("Failed to allocate page request entry\n");
		return;
	}

	entry->vaddr = vaddr;
	entry->nr_pages = nr_pages;
	entry->sk = sk;
	entry->dst_id = dst_id;

	pr_debug("Requesting page at %lx (nr_pages=%lu, dst_id=%lu)\n", vaddr, nr_pages, dst_id);

	/* Location will be looked up on first access */
	entry->ppb = NULL;
	entry->seg_idx = 0;
	entry->page_idx_in_seg = 0;
	entry->location_found = false;

	if (spsc_enqueue(page_request_tail, page_request_queue_size,
			 entry, struct page_request_spsc_node)) {
		pr_err("Failed to allocate SPSC node for page request\n");
		xfree(entry);
	}
}

/* Lock-free SPSC dequeue (Thread 3 consumes page requests) */
static struct page_request_entry *get_next_page_request(void)
{
	return spsc_dequeue(page_request_head, page_request_queue_size);
}

/* Lock-free check if queue has requests */
static bool has_page_requests(void)
{
	return spsc_peek(page_request_head);
}

/* Get approximate queue size (counter may lag due to RELAXED ordering) */
static unsigned long get_page_request_queue_size(void)
{
	return spsc_size(page_request_queue_size);
}

struct active_image {
	u64 dst_id;
	int main_sk;
	unsigned long total_pages;
	unsigned long remaining_pages;
	unsigned long total_cow_pages;
	unsigned long total_req_pages;
	
	struct list_head list;
};

static LIST_HEAD(active_images_queue);
static pthread_spinlock_t active_images_lock;
static pthread_once_t active_images_lock_once = PTHREAD_ONCE_INIT;

/* Single global background thread */
static pthread_t g_unified_thread;
static _Atomic bool g_unified_thread_running = false;
static _Atomic bool g_unified_thread_stop = false;

/* Forward declaration */
static void cleanup_active_images_queue(void);

void wait_for_page_server_thread(void)
{
	if (!g_unified_thread_running)
		return;
	pr_info("Waiting for page server thread to finish...\n");
	pthread_join(g_unified_thread, NULL);
	g_unified_thread_running = false;
	pr_info("Page server thread finished\n");

	/* Clean up any remaining active images to prevent memory leak */
	cleanup_active_images_queue();
}

/* Active image tracking for unified background thread */


static void init_active_images_lock_once(void)
{
	pthread_spin_init(&active_images_lock, PTHREAD_PROCESS_PRIVATE);
}

static void init_active_images_queue(void)
{
	pthread_once(&active_images_lock_once, init_active_images_lock_once);
}

static void cleanup_active_images_queue(void)
{
	struct active_image *img, *tmp;

	/* If list is empty, nothing to free and lock may not be initialized */
	if (list_empty(&active_images_queue))
		return;

	/* Init ensures lock is ready (pthread_once guarantees single init) */
	init_active_images_queue();

	pthread_spin_lock(&active_images_lock);
	list_for_each_entry_safe(img, tmp, &active_images_queue, list) {
		list_del(&img->list);
		if (img->main_sk >= 0)
			close(img->main_sk);
		xfree(img);
	}
	pthread_spin_unlock(&active_images_lock);

	pthread_spin_destroy(&active_images_lock);
}

static struct active_image *find_active_image(u64 dst_id)
{
	struct active_image *img;
	
	/* Caller must hold lock */
	list_for_each_entry(img, &active_images_queue, list) {
		if (img->dst_id == dst_id)
			return img;
	}
	return NULL;
}

static int add_active_image(u64 dst_id, int sk)
{
	struct active_image *img;
	unsigned long total_pages;
	
	pthread_spin_lock(&active_images_lock);
	
	/* Check if already active */
	if (find_active_image(dst_id)) {
		pthread_spin_unlock(&active_images_lock);
		pr_info("Image dst_id=%lu already active\n", dst_id);
		return 0;
	}
	
	pthread_spin_unlock(&active_images_lock);
	
	/* Count total pages in lazy VMAs for this dst_id (uses global list) */
	total_pages = count_lazy_vma_pages(dst_id);

	if (total_pages == 0) {
		pr_err("Image dst_id=%lu matched ZERO lazy VMA pages\n", dst_id);
		return 0;  /* Nothing to send */
	}
	
	/* Create active image entry */
	img = xzalloc(sizeof(*img));
	if (!img) {
		pr_err("Failed to allocate active image\n");
		return -1;
	}
	
	img->dst_id = dst_id;
	img->main_sk = sk;
	img->total_pages = total_pages;
	img->remaining_pages = total_pages;
	img->total_cow_pages = 0;
	img->total_req_pages = 0;
	
	INIT_LIST_HEAD(&img->list);
	
	pthread_spin_lock(&active_images_lock);
	list_add_tail(&img->list, &active_images_queue);
	pthread_spin_unlock(&active_images_lock);
	
	pr_info("Added active image dst_id=%lu with %lu lazy VMA pages\n",
		dst_id, total_pages);
	return 0;
}
/* Timing statistics for COW page flow (accumulated in nanoseconds, printed once/sec) */
static struct {
	unsigned long vma_lookup_total_ns;
	unsigned long vma_lookup_count;
	unsigned long send_page_total_ns;
	unsigned long send_page_count;
	unsigned long queue_dequeue_total_ns;
	unsigned long queue_dequeue_count;
	/* Sub-timing within send_lazy_vma_page (nanoseconds) */
	unsigned long send_vm_readv_ns;
	unsigned long send_compress_ns;
	unsigned long send_unprotect_ns;
	unsigned long send_sub_count;
} cow_timing;

/*
 * Helper to send a non-COW lazy VMA page using process_vm_readv.
 *
 * This function is now only called for pages where cow_bitmap=0,
 * meaning the source process has NOT written to this page. The live
 * memory still contains the original snapshot-consistent data.
 */
static int send_lazy_vma_page(int sk, unsigned long vaddr, u64 dst_id, pid_t source_pid)
{
	void *buffer;
	int ret;
	int uffd;
	struct iovec local_iov, remote_iov;
	struct timespec t_start, t_readv, t_socket, t_unprot, t_end;

	pr_debug("[SEND_PAGE] Sending non-COW page at vaddr=0x%lx pid=%d\n",
		 vaddr, source_pid);

	clock_gettime(CLOCK_MONOTONIC, &t_start);


	buffer = xmalloc(PAGE_SIZE);
	if (!buffer)
		return -1;

	/* Read directly from process memory (safe — page not modified) */
	local_iov.iov_base = buffer;
	local_iov.iov_len = PAGE_SIZE;
	remote_iov.iov_base = (void *)vaddr;
	remote_iov.iov_len = PAGE_SIZE;

	ret = process_vm_readv(source_pid, &local_iov, 1, &remote_iov, 1, 0);
	clock_gettime(CLOCK_MONOTONIC, &t_readv);

	if (ret != PAGE_SIZE) {
		pr_perror("Failed to read page at %lx from pid %d", vaddr, source_pid);
		xfree(buffer);
		return -1;
	}

	/* Compress and send */
	ret = send_page_compressed(sk, buffer, dst_id, vaddr);
	clock_gettime(CLOCK_MONOTONIC, &t_socket);
	xfree(buffer);

	if (ret != 0) {
		pr_perror("Failed to send page at 0x%lx", vaddr);
		return -1;
	}

	/* Unprotect page — it's been sent, no need to track writes anymore */
	uffd = cow_get_uffd_for_pid(source_pid);
	if (uffd >= 0) {
		struct uffdio_writeprotect wp;
		wp.range.start = vaddr;
		wp.range.len = PAGE_SIZE;
		wp.mode = 0;
		if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp))
			pr_perror("Failed to unprotect page at 0x%lx", vaddr);
	}
	clock_gettime(CLOCK_MONOTONIC, &t_unprot);

	/* Accumulate timing stats */
	clock_gettime(CLOCK_MONOTONIC, &t_end);
	cow_timing.send_vm_readv_ns += (t_readv.tv_sec - t_start.tv_sec) * 1000000000 +
				       (t_readv.tv_nsec - t_start.tv_nsec);
	cow_timing.send_compress_ns += (t_socket.tv_sec - t_readv.tv_sec) * 1000000000 +
				       (t_socket.tv_nsec - t_readv.tv_nsec);
	cow_timing.send_unprotect_ns += (t_unprot.tv_sec - t_socket.tv_sec) * 1000000000 +
					(t_unprot.tv_nsec - t_socket.tv_nsec);
	cow_timing.send_sub_count++;

	return 1;  /* 1 = page sent, 0 = race/discard, -1 = error */
}



/* Helper to send a COW page from lazy VMA */
static int send_cow_page_lazy(struct cow_page_queue_entry *entry, struct active_image *img, pid_t source_pid)
{
	struct lazy_vma_entry *lve;
	unsigned long page_idx;
	int ret;
	struct timespec t1, t2;
	
	/* Time VMA lookup */
	clock_gettime(CLOCK_MONOTONIC, &t1);
	
	/* Find which lazy VMA contains this page (uses global list) */
	lve = find_lazy_vma_for_addr(entry->vaddr, img->dst_id);
	
	clock_gettime(CLOCK_MONOTONIC, &t2);
	cow_timing.vma_lookup_total_ns += (t2.tv_sec - t1.tv_sec) * 1000000000 + (t2.tv_nsec - t1.tv_nsec);
	cow_timing.vma_lookup_count++;
	
	if (!lve) {
		pr_err("COW page 0x%lx not in any lazy VMA (dst_id=%lu)\n",
		       entry->vaddr, img->dst_id);
		return -1;
	}
	/* Calculate page index within VMA */
	page_idx = (entry->vaddr - lve->start) / PAGE_SIZE;
	
	/* Check if already sent */
	if (bitmap_test_nonatomic(lve->sent_bitmap, page_idx)) {
		pr_debug("COW page 0x%lx already sent\n", entry->vaddr);
		return 0;
	}

	if (!entry->data) {
		pr_err("COW queue entry 0x%lx has no data!\n", entry->vaddr);
		return -1;
	}

	/* Time page send */
	clock_gettime(CLOCK_MONOTONIC, &t1);

	ret = send_page_compressed(img->main_sk, entry->data, img->dst_id,
				   entry->vaddr);

	clock_gettime(CLOCK_MONOTONIC, &t2);
	cow_timing.send_page_total_ns += (t2.tv_sec - t1.tv_sec) * 1000000000 + (t2.tv_nsec - t1.tv_nsec);
	cow_timing.send_page_count++;

	if (ret < 0) {
		pr_warn("Failed to send COW page 0x%lx, re-queueing for retry\n", entry->vaddr);
		cow_put_back_page(entry);
		return -2;  /* Special: entry put back for retry, caller must NOT free it */
	}

	/* Mark as sent */
	bitmap_set_nonatomic(lve->sent_bitmap, page_idx);

	return 1;  /* Successfully sent */
}

/* Helper to send a page request from lazy VMA */
static int send_request_page_lazy(struct page_request_entry *req, struct active_image *img, pid_t source_pid)
{
	unsigned long i;
	int ret;
	int sent_count = 0;

	/* Send multiple pages if requested */
	for (i = 0; i < req->nr_pages; i++) {
		unsigned long page_vaddr = req->vaddr + (i * PAGE_SIZE);
		struct lazy_vma_entry *lve;
		unsigned long page_idx;
		/* Find which lazy VMA contains this page (uses global list) */
		lve = find_lazy_vma_for_addr(page_vaddr, req->dst_id);
		if (!lve) {
			pr_err("Request page 0x%lx not in any lazy VMA\n", page_vaddr);
			return -1;
		}
		
		/* Calculate page index within VMA */
		page_idx = (page_vaddr - lve->start) / PAGE_SIZE;
		
		/* Check if already sent */
		if (bitmap_test_nonatomic(lve->sent_bitmap, page_idx)) {
			pr_debug("Request page 0x%lx already sent, skipping\n", page_vaddr);
			continue;
		}

		/*
		 * Check cow_bitmap. If the page was write-faulted,
		 * the original data is in the P1 queue. We cannot read
		 * live memory because it contains post-write data.
		 * Skip and let P1 handle it — drain_cow_pages runs
		 * before drain_page_requests in the main loop.
		 *
		 * If we get here with cow_bitmap=1, it means a fault
		 * arrived AFTER the latest P1 drain. Next loop iteration
		 * will drain it.
		 */
		if (lve->cow_bitmap &&
		    atomic_bitmap_test(lve->cow_bitmap, page_idx)) {
			pr_debug("P2: page 0x%lx is COW, skipping for P1\n",
				 page_vaddr);
			continue;
		}

		/* Page is not modified — send live data */
		ret = send_lazy_vma_page(req->sk, page_vaddr, req->dst_id, source_pid);
		if (ret < 0)
			return -1;

		/* Mark as sent (ret == 1 means success) */
		bitmap_set_nonatomic(lve->sent_bitmap, page_idx);
		sent_count++;
	}
	
	return sent_count;  /* Return number of pages actually sent */
}


/* Thread statistics context */
struct unified_thread_stats {
	time_t last_print_time;
	unsigned long priority1_pages;  /* COW pages sent by P1 */
	unsigned long priority2_pages;  /* Request pages sent by P2 */
	unsigned long priority3_pages;  /* Regular pages sent by P3 */
	unsigned long skip_already_sent; /* P3 skipped: already in sent_bitmap */
	unsigned long skip_cow_bitmap;   /* P3 skipped: marked COW, waiting for P1 */
};

static void print_thread_stats(struct unified_thread_stats *stats)
{
	unsigned long cow_queue = cow_get_pages_queue_size();
	unsigned long req_queue = get_page_request_queue_size();
	float compress_ratio = 0.0;
	struct timespec ts;
	struct tm *tm;

	if (g_compress_uncompressed_bytes > 0)
		compress_ratio = (float)g_compress_compressed_bytes * 100.0 /
				 g_compress_uncompressed_bytes;

	clock_gettime(CLOCK_REALTIME, &ts);
	tm = localtime(&ts.tv_sec);

	pr_err("[UNIFIED_THREAD_STATS] [%02d:%02d:%02d.%03ld] P1(COW)=%lu P2(Req)=%lu P3(Reg)=%lu | Skip: sent=%lu cow=%lu | COW_Q=%lu Req_Q=%lu | Compress: %lu->%lu (%.1f%%)\n",
		tm->tm_hour, tm->tm_min, tm->tm_sec, ts.tv_nsec / 1000000,
		stats->priority1_pages, stats->priority2_pages,
		stats->priority3_pages,
		stats->skip_already_sent, stats->skip_cow_bitmap,
		cow_queue, req_queue,
		g_compress_uncompressed_bytes, g_compress_compressed_bytes,
		compress_ratio);

	pr_err("[COW_TIMING] Queue: %lu ns (%lu ops) | VMA_lookup: %lu ns (%lu ops) | Send: %lu ns (%lu ops)\n",
		cow_timing.queue_dequeue_total_ns, cow_timing.queue_dequeue_count,
		cow_timing.vma_lookup_total_ns, cow_timing.vma_lookup_count,
		cow_timing.send_page_total_ns, cow_timing.send_page_count);

	if (cow_timing.send_sub_count > 0) {
		pr_debug("[SEND_BREAKDOWN] readv=%lu compress+send=%lu unprot=%lu ns (avg per %lu ops)\n",
			cow_timing.send_vm_readv_ns / cow_timing.send_sub_count,
			cow_timing.send_compress_ns / cow_timing.send_sub_count,
			cow_timing.send_unprotect_ns / cow_timing.send_sub_count,
			cow_timing.send_sub_count);
	}

	/* Reset counters */
	g_compress_uncompressed_bytes = 0;
	g_compress_compressed_bytes = 0;
	memset(&cow_timing, 0, sizeof(cow_timing));
	stats->priority1_pages = 0;
	stats->priority2_pages = 0;
	stats->priority3_pages = 0;
	stats->skip_already_sent = 0;
	stats->skip_cow_bitmap = 0;
}

static void maybe_print_stats(struct unified_thread_stats *stats)
{
	time_t now = time(NULL);

	if (now - stats->last_print_time >= 1) {
		print_thread_stats(stats);
		stats->last_print_time = now;
	}
}

/*
 * Drain pending COW pages (Priority 1)
 * Returns: number of pages sent, or -1 on error
 */
static int drain_cow_pages(struct active_image *img, pid_t source_pid,
			   int max_pages, struct unified_thread_stats *stats)
{
	int sent = 0;

	while (max_pages > 0 && cow_has_pending_pages() && img->remaining_pages > 0) {
		struct cow_page_queue_entry *entry;
		struct timespec tq1, tq2;
		int ret;

		clock_gettime(CLOCK_MONOTONIC, &tq1);
		entry = cow_get_next_page();
		clock_gettime(CLOCK_MONOTONIC, &tq2);
		cow_timing.queue_dequeue_total_ns +=
			(tq2.tv_sec - tq1.tv_sec) * 1000000000 +
			(tq2.tv_nsec - tq1.tv_nsec);
		cow_timing.queue_dequeue_count++;

		if (!entry)
			break;

		ret = send_cow_page_lazy(entry, img, source_pid);

		/* Check return code BEFORE freeing entry */
		if (ret == -2) {
			/* Entry was put back for retry, don't free it */
			max_pages--;
			continue;
		}

		/* Free entry for all other cases (success, skip, or fatal error) */
		if (entry->data)
			xfree(entry->data);
		xfree(entry);

		if (ret < 0) {
			pr_err("Failed to send COW page (fatal error)\n");
			return -1;
		}

		if (ret > 0) {
			img->total_cow_pages++;
			img->remaining_pages--;
			stats->priority1_pages++;
			sent++;
		}
		max_pages--;
	}

	return sent;
}

/*
 * Drain pending page requests (Priority 2)
 * Returns: number of pages sent, or -1 on error
 */
static int drain_page_requests(struct active_image *img, pid_t source_pid,
			       struct unified_thread_stats *stats)
{
	int sent = 0;

	while (has_page_requests() && img->remaining_pages > 0) {
		struct page_request_entry *req = get_next_page_request();
		int ret;

		if (!req)
			break;

		ret = send_request_page_lazy(req, img, source_pid);

		if (ret > 0) {
			img->total_req_pages += ret;
			img->remaining_pages -= ret;
			stats->priority2_pages += ret;
			sent += ret;
		}

		xfree(req);

		if (ret < 0) {
			pr_err("Failed to send request page\n");
			return -1;
		}
	}

	return sent;
}

/*
 * Send a single lazy VMA page (Priority 3)
 * Returns: 1 if sent, 0 if skipped, -1 on error
 */
static int send_single_lazy_page(struct active_image *img,
				 struct lazy_vma_entry *lve,
				 unsigned long vaddr, unsigned long page_idx,
				 pid_t source_pid,
				 struct unified_thread_stats *stats)
{
	int ret;

	/* Check if already sent */
	if (bitmap_test_nonatomic(lve->sent_bitmap, page_idx)) {
		stats->skip_already_sent++;
		return 0;
	}

	if (lve->cow_bitmap &&
	    atomic_bitmap_test(lve->cow_bitmap, page_idx)) {
		stats->skip_cow_bitmap++;
		return 0;
	}

	ret = send_lazy_vma_page(img->main_sk, vaddr, img->dst_id, source_pid);
	if (ret < 0) {
		pr_err("Failed to send lazy VMA page at %lx\n", vaddr);
		return -1;
	}

	/* Mark as sent (ret == 1 means success) */
	bitmap_set_nonatomic(lve->sent_bitmap, page_idx);
	img->remaining_pages--;
	stats->priority3_pages++;

	return 1;
}

/* Send completion marker to destination */
static int send_image_complete(struct active_image *img)
{
	struct page_server_iov close_cmd = {
		.cmd = PS_IOV_CLOSE,
		.nr_pages = 0,
		.vaddr = 0,
		.dst_id = img->dst_id,
	};

	pr_warn("Image dst_id=%lu complete: %lu total pages (%lu COW, %lu req)\n",
		img->dst_id, img->total_pages,
		img->total_cow_pages, img->total_req_pages);

	/* Send close command */
	if (send_psi(img->main_sk, &close_cmd)) {
		if (errno == EPIPE || errno == ECONNRESET) {
			pr_info("Receiver closed after close marker, treating as completion\n");
			return 0;
		}
		pr_err("Failed to send close command\n");
		return -1;
	}
	return 0;
}

/*
 * Process all pages for a single VMA
 * Returns: 0 on success, -1 on error
 */
static int process_vma_pages(struct active_image *img,
			     struct lazy_vma_entry *lve,
			     pid_t source_pid,
			     struct unified_thread_stats *stats)
{
	unsigned long vaddr;
	unsigned long page_idx = 0;

	pr_debug("Processing VMA: %lx-%lx len=%lu\n",
		 lve->start, lve->end, lve->end - lve->start);

	for (vaddr = lve->start; vaddr < lve->end; vaddr += PAGE_SIZE, page_idx++) {
		maybe_print_stats(stats);

		/*
		 * P1: Drain pending COW pages in bounded batches.
		 * A batch limit ensures P2 (urgent page fault requests)
		 * and P3 (sequential scan) are not starved under heavy
		 * writes. COW pages skipped by P3 (bitmap check) are
		 * sent by P1 in subsequent iterations or final_queue_drain().
		 */
		if (drain_cow_pages(img, source_pid, 100, stats) < 0)
			return -1;

		/* Priority 2: Drain page requests */
		if (drain_page_requests(img, source_pid, stats) < 0)
			return -1;

		/* Priority 3: Send this lazy VMA page */
		if (send_single_lazy_page(img, lve, vaddr, page_idx,
					  source_pid, stats) < 0)
			return -1;
	}

	return 0;
}

/*
 * Final drain of COW and request queues after all VMAs processed
 * Returns: 0 on success, -1 on error
 */
static int final_queue_drain(struct active_image *img, pid_t source_pid,
			     struct unified_thread_stats *stats)
{
	while (img->remaining_pages > 0) {
		int cow_sent, req_sent;

		/*
		 * Drain COW pages in batches so that P2 (page fault
		 * requests) is still served after P3 scan completes.
		 */
		cow_sent = drain_cow_pages(img, source_pid, 100, stats);
		if (cow_sent < 0)
			return -1;

		req_sent = drain_page_requests(img, source_pid, stats);
		if (req_sent < 0)
			return -1;

		/* No more pending work */
		if (cow_sent == 0 && req_sent == 0)
			break;
	}

	return 0;
}

/* Unified background thread serving all images */
static void *unified_page_server_thread(void *arg)
{
	struct unified_thread_stats stats = { 0 };

	pthread_setname_np(pthread_self(), "criu-page-srv");
	pr_info("Unified page server thread started\n");

	while (!g_unified_thread_stop) {
		struct active_image *img, *tmp;

		pthread_spin_lock(&active_images_lock);

		list_for_each_entry_safe(img, tmp, &active_images_queue, list) {
			struct lazy_vma_entry *lve;
			pid_t source_pid = 0;

			pthread_spin_unlock(&active_images_lock);

			pr_info("Processing image dst_id=%lu remaining=%lu pages\n",
				img->dst_id, img->remaining_pages);

			/* Process each lazy VMA */
			list_for_each_entry(lve, get_global_lazy_vmas(), list) {
				if (lve->dst_id != img->dst_id)
					continue;

				source_pid = lve->source_pid;

				if (process_vma_pages(img, lve, source_pid, &stats) < 0) {
					pr_err("Error processing VMA %lx-%lx\n",
					       lve->start, lve->end);
					break;
				}
			}

			/* Final drain of any remaining queued pages */
			pthread_spin_lock(&active_images_lock);
			if (final_queue_drain(img, source_pid, &stats) < 0) {
				pr_err("Error in final queue drain\n");
			}
			if (img->remaining_pages == 0) {
				pthread_spin_unlock(&active_images_lock);
				if (send_image_complete(img) < 0)
					pr_err("Failed to complete image dst_id=%lu\n",
					       img->dst_id);
				pthread_spin_lock(&active_images_lock);
				list_del(&img->list);
				xfree(img);
				continue;
			}

			pr_err("Failed processing image dst_id=%lu remaining_pages=%lu, closing stream\n",
			       img->dst_id, img->remaining_pages);
			shutdown(img->main_sk, SHUT_RDWR);
			list_del(&img->list);
			xfree(img);
		}

		g_unified_thread_stop = list_empty(&active_images_queue);
		pthread_spin_unlock(&active_images_lock);
	}

	pr_err("Unified page server thread stopped\n");
	g_unified_thread_running = false;
	return NULL;
}

static int page_server_get_all_pages(int sk, struct page_server_iov *pi)
{
	int ret;
	
	pr_warn("Adding image dst_id=%lu to batch transfer queue\n", pi->dst_id);
	
	/* Initialize queues */
	init_active_images_queue();
	init_page_request_queue();
	
	/* Add this image to active queue */
	ret = add_active_image(pi->dst_id, sk);
	if (ret < 0)
		return -1;
	
	/* Start unified thread if not already running */
	if (!g_unified_thread_running) {
		pr_info("Starting unified page server thread\n");
		g_unified_thread_stop = false;
		ret = pthread_create(&g_unified_thread, NULL, unified_page_server_thread, NULL);
		if (ret) {
			pr_perror("Failed to create unified thread");
			return -1;
		}
		g_unified_thread_running = true;
	}
	
	return 0;
}

static int page_server_get_pages(int sk, struct page_server_iov *pi)
{
	unsigned long i;
	
	/* Split multi-page requests into individual page requests */
	for (i = 0; i < pi->nr_pages; i++) {
		add_page_request(pi->vaddr + (i * PAGE_SIZE), 1, sk, pi->dst_id);
	}
	
	pr_debug("Split and enqueued %lu page requests starting at vaddr=%lx\n", 
		 (unsigned long)pi->nr_pages, (unsigned long)pi->vaddr);
	
	/* Return immediately - background thread will send the response */
	return 0;
}
extern void pstree_switch_state(struct pstree_item *root_item, int st);
static int page_server_serve(int sk)
{
	int ret = -1;
	bool flushed = false;
	bool receiving_pages = !opts.lazy_pages;

	if (receiving_pages) {
		/*
		 * This socket only accepts data except one thing -- it
		 * writes back the has_parent bit from time to time, so
		 * make it NODELAY all the time.
		 */
		tcp_nodelay(sk, true);

		if (pipe(cxfer.p)) {
			pr_perror("Can't make pipe for xfer");
			close(sk);
			return -1;
		}

		cxfer.pipe_size = fcntl(cxfer.p[0], F_GETPIPE_SZ, 0);
		pr_debug("Created xfer pipe size %u\n", cxfer.pipe_size);
	} else {
		pipe_read_dest_init(&pipe_read_dest);
		tcp_cork(sk, true);
	}


	/* Initialize page request queue on first use */
	init_page_request_queue();

	while (1) {
		struct page_server_iov pi;
		u32 cmd;

		ret = __recv(sk, &pi, sizeof(pi), MSG_WAITALL);

		if (!ret)
			break;

		if (ret != sizeof(pi)) {
			pr_perror("Can't read pagemap from socket");
			ret = -1;
			break;
		}

		flushed = false;
		cmd = decode_ps_cmd(pi.cmd);

		/* Check and print stats on each iteration */
		check_and_print_stats();

		switch (cmd) {
		case PS_IOV_OPEN:
			ps_stats.serve_open++;
			ret = page_server_open(-1, &pi);
			break;
		case PS_IOV_OPEN2:
			ps_stats.serve_open2++;
			ret = page_server_open(sk, &pi);
			break;
		case PS_IOV_PARENT:
			ps_stats.serve_parent++;
			ret = page_server_check_parent(sk, &pi);
			break;
		case PS_IOV_ADD_F_COMPRESS:
		case PS_IOV_ADD_F:
		case PS_IOV_ADD_F_PF:
		case PS_IOV_ADD:
		case PS_IOV_HOLE: {
			u32 flags;
			if (cmd == PS_IOV_ADD_F_PF)
			{
				cmd = PS_IOV_ADD_F;
				pr_err("PS_IOV_ADD_F_PF %" PRIx64 " - %" PRIx64 "\n",
		 				pi.vaddr, pi.vaddr + pi.nr_pages * PAGE_SIZE);				
			}
			if (likely(cmd == PS_IOV_ADD_F || cmd == PS_IOV_ADD_F_COMPRESS)) {
				flags = decode_ps_flags(pi.cmd);
				ps_stats.serve_add_f++;
			}
			else if (cmd == PS_IOV_ADD){
				flags = PE_PRESENT;
				ps_stats.serve_add++;
			}
			else /* PS_IOV_HOLE */
			{
				flags = PE_PARENT;
				ps_stats.serve_hole++;
			}

			ret = page_server_add(sk, &pi, flags, cmd == PS_IOV_ADD_F_COMPRESS);
			break;
			}
		case PS_IOV_CLOSE:
		case PS_IOV_FORCE_CLOSE: {
			int32_t status = 0;

			ret = 0;
			
			if (cmd == PS_IOV_CLOSE)
				ps_stats.serve_close++;
			else
				ps_stats.serve_force_close++;

			/*
			 * An answer must be sent back to inform another side,
			 * that all data were received
			 */
			pr_info("Got close; sending completion status\n");
			if (__send(sk, &status, sizeof(status), 0) != sizeof(status)) {
				pr_perror("Can't send the final package");
				ret = -1;
			}

			flushed = true;
			break;
		}
		case PS_IOV_GET:
			ps_stats.serve_get++;
			ret = page_server_get_pages(sk, &pi);
			break;
		case PS_IOV_GET_ALL:
			ps_stats.serve_get++;
			ret = page_server_get_all_pages(sk, &pi);
			break;
		default:
			pr_err("Unknown command %u\n", pi.cmd);
			ps_stats.serve_unknown++;
			ret = -1;
			break;
		}

		if (ret){
			break;
		}
		if (pi.cmd == PS_IOV_CLOSE || pi.cmd == PS_IOV_FORCE_CLOSE){
		
			break;
		}
	}

	if (receiving_pages && !ret && !flushed) {
		pr_err("The data were not flushed\n");
		ret = -1;
	}

	tls_terminate_session(ret != 0);

	if (ret == 0 && opts.ps_socket == -1) {
		char c;

		/*
		 * Wait when a remote side closes the connection
		 * to avoid TIME_WAIT bucket
		 */
		if (read(sk, &c, sizeof(c)) != 0) {
			pr_perror("Unexpected data");
			ret = -1;
		}
	}

	page_server_close();

	pr_info("Session over\n");

	close(sk);
	return ret;
}

static int fill_page_pipe(struct page_read *pr, struct page_pipe *pp)
{
	struct page_pipe_buf *ppb;
	int i, ret;

	pr->reset(pr);

	while (pr->advance(pr)) {
		unsigned long vaddr = pr->pe->vaddr;

		for (i = 0; i < pr->pe->nr_pages; i++, vaddr += PAGE_SIZE) {
			if (pagemap_in_parent(pr->pe))
				ret = page_pipe_add_hole(pp, vaddr, PP_HOLE_PARENT);
			else
				ret = page_pipe_add_page(pp, vaddr, pagemap_lazy(pr->pe) ? PPB_LAZY : 0);
			if (ret) {
				pr_err("Failed adding page at %lx\n", vaddr);
				return -1;
			}
		}
	}

	list_for_each_entry(ppb, &pp->bufs, l) {
		for (i = 0; i < ppb->nr_segs; i++) {
			struct iovec iov = ppb->iov[i];

			if (splice(img_raw_fd(pr->pi), NULL, ppb->p[1], NULL, iov.iov_len, SPLICE_F_MOVE) !=
			    iov.iov_len) {
				pr_perror("Splice failed");
				return -1;
			}
		}
	}

	debug_show_page_pipe(pp);

	return 0;
}

static int page_pipe_from_pagemap(struct page_pipe **pp, int pid)
{
	struct page_read pr;
	unsigned long nr_pages = 0;
	int ret = -1;

	if (open_page_read(pid, &pr, PR_TASK) <= 0) {
		pr_err("Failed to open page read for %d\n", pid);
		return -1;
	}

	while (pr.advance(&pr))
		if (pagemap_present(pr.pe))
			nr_pages += pr.pe->nr_pages;

	*pp = create_page_pipe(nr_pages, NULL, 0);
	if (!*pp) {
		pr_err("Cannot create page pipe for %d\n", pid);
		goto err;
	}

	if (fill_page_pipe(&pr, *pp))
		goto err_pp;

	ret = 0;
err:
	pr.close(&pr);
	return ret;
err_pp:
	destroy_page_pipe(*pp);
	*pp = NULL;
	goto err;
}

static int page_server_init_send(void)
{
	struct pstree_item *pi;
	struct page_pipe *pp;

	BUILD_BUG_ON(sizeof(struct dmp_info) > sizeof(struct rst_info));

	if (prepare_dummy_pstree())
		return -1;

	for_each_pstree_item(pi) {
		if (prepare_dummy_task_state(pi))
			return -1;

		if (!task_alive(pi))
			continue;

		if (page_pipe_from_pagemap(&pp, vpid(pi))) {
			pr_err("%d: failed to open page-read\n", vpid(pi));
			return -1;
		}

		/*
		 * prepare_dummy_pstree presumes 'restore' behaviour,
		 * but page_server_get_pages uses dmpi() to get access
		 * to the page-pipe, so we are faking it here.
		 */
		memset(rsti(pi), 0, sizeof(struct rst_info));
		dmpi(pi)->mem_pp = pp;
	}

	return 0;
}

int cr_page_server(bool daemon_mode, bool lazy_dump, int cfd)
{
	int ask = -1;
	int sk = -1;
	int ret;

	/*
	 * When running inside the dump process (lazy_dump=true), stats are
	 * already initialized by cr_dump_tasks(). Re-initializing them here
	 * would reset counters/timings and make dump stats meaningless.
	 */
	if (!lazy_dump && init_stats(DUMP_STATS))
		return -1;

	if (!opts.lazy_pages)
		up_page_ids_base();
	else if (!lazy_dump)
		if (page_server_init_send())
			return -1;

	if (opts.ps_socket != -1) {
		ask = opts.ps_socket;
		pr_info("Reusing ps socket %d\n", ask);
		goto no_server;
	}

	sk = setup_tcp_server("page", opts.addr, &opts.port);
	if (sk == -1)
		return -1;

	/*
	 * The TCP socket is now bound and listening.  Signal readiness
	 * so the replica can connect.  This marker MUST come after
	 * listen() — writing it earlier caused a race where the
	 * replica tried to connect before the socket was ready.
	 */
	if (opts.cow_dump && lazy_dump)
		pr_err("PAGE SERVER READY TO SERVE\n");

no_server:

	if (!daemon_mode && cfd >= 0) {
		struct ps_info info = { .pid = getpid(), .port = opts.port };
		int count;

		count = write(cfd, &info, sizeof(info));
		close_safe(&cfd);
		if (count != sizeof(info)) {
			pr_perror("Unable to write ps_info");
			exit(1);
		}
	}

	ret = run_tcp_server(daemon_mode, &ask, cfd, sk);
	if (ret != 0)
		return ret > 0 ? 0 : -1;

	if (tls_x509_init(ask, true)) {
		close_safe(&sk);
		return -1;
	}

	if (ask >= 0)
		ret = page_server_serve(ask);

	if (daemon_mode)
		exit(ret);

	return ret;
}

static int connect_to_page_server(void)
{
	if (!opts.use_page_server)
		return 0;

	if (opts.ps_socket != -1) {
		page_server_sk = opts.ps_socket;
		pr_info("Reusing ps socket %d\n", page_server_sk);
		goto out;
	}

	page_server_sk = setup_tcp_client(opts.addr);
	if (page_server_sk == -1)
		return -1;

	if (tls_x509_init(page_server_sk, false)) {
		close(page_server_sk);
		return -1;
	}
out:
	/*
	 * CORK the socket at the very beginning. As per ANK
	 * the corked by default socket with sporadic NODELAY-s
	 * on urgent data is the smartest mode ever.
	 */
	tcp_cork(page_server_sk, true);
	return 0;
}

int connect_to_page_server_to_send(void)
{
	return connect_to_page_server();
}

int disconnect_from_page_server(void)
{
	struct page_server_iov pi = {};
	int32_t status = -1;
	int ret = -1;

	if (!opts.use_page_server)
		return 0;

	if (page_server_sk == -1)
		return 0;

	pr_err("Disconnect from the page server\n");

	if (opts.ps_socket != -1)
		/*
		 * The socket might not get closed (held by
		 * the parent process) so we must order the
		 * page-server to terminate itself.
		 */
		pi.cmd = PS_IOV_FORCE_CLOSE;
	else
		pi.cmd = PS_IOV_CLOSE;

	if (send_psi(page_server_sk, &pi))
		goto out;

	if (__recv(page_server_sk, &status, sizeof(status), 0) != sizeof(status)) {
		pr_perror("The page server doesn't answer");
		goto out;
	}

	ret = 0;
out:
	tls_terminate_session(ret != 0);
	close_safe(&page_server_sk);

	return ret ?: status;
}

struct ps_async_read {
	unsigned long rb; /* read bytes */
	unsigned long goal;
	unsigned long nr_pages;

	struct page_server_iov pi;
	void *pages;

	ps_async_read_complete complete;
	void *priv;

	struct list_head l;

	/* Compression support */
	int compressed_size;     /* Size of compressed data (0 = uncompressed) */
	int compressed_rb;       /* Bytes read of compressed data */
	char *compressed_buf;    /* Buffer for compressed data */
	int compress_state;      /* 0=reading header, 1=reading size, 2=reading data */
};

static LIST_HEAD(async_reads);

static inline void async_read_set_goal(struct ps_async_read *ar, unsigned long nr_pages)
{
	ar->goal = sizeof(ar->pi) + nr_pages * PAGE_SIZE;
	ar->nr_pages = nr_pages;
}

static void init_ps_async_read(struct ps_async_read *ar, void *buf, unsigned long nr_pages, ps_async_read_complete complete,
			       void *priv)
{
	ar->pages = buf;
	ar->rb = 0;
	ar->complete = complete;
	ar->priv = priv;
	async_read_set_goal(ar, nr_pages);
}

static int page_server_start_async_read(void *buf, unsigned long nr_pages, ps_async_read_complete complete, void *priv)
{
	struct ps_async_read *ar;

	ar = xmalloc(sizeof(*ar));
	if (ar == NULL)
		return -1;

	init_ps_async_read(ar, buf, nr_pages, complete, priv);
	list_add_tail(&ar->l, &async_reads);
	return 0;
}
static struct {
	unsigned long recv_calls;
	unsigned long recv_would_block;
	unsigned long recv_bytes;
	unsigned long recv_wait_time_ns;
	unsigned long pages_completed;
	unsigned long decompress_calls;
	unsigned long decompress_time_ns;
	unsigned long callback_calls;
	time_t last_print_time;
} bulk_stats;

/*
 * Bulk mode continuous stream reader.
 * Processes headers and pages as they arrive without correlation to requests.
 * The server's background thread sends pages continuously.
 * Supports compressed pages (PS_IOV_ADD_F_COMPRESS).
 */
static int page_server_read_bulk_stream(struct ps_async_read *ar, int flags)
{
	int ret, need;
	void *buf;
	u32 cmd;

	/* Reading header */
	if (ar->compress_state == COMPRESS_STATE_READING_HEADER) {
		if (ar->rb < sizeof(ar->pi)) {
			struct timespec t_recv_start, t_recv_end;

			buf = ((void *)&ar->pi) + ar->rb;
			need = sizeof(ar->pi) - ar->rb;

			clock_gettime(CLOCK_MONOTONIC, &t_recv_start);
			bulk_stats.recv_calls++;
			ret = __recv(page_server_sk, buf, need, flags);
			clock_gettime(CLOCK_MONOTONIC, &t_recv_end);
			bulk_stats.recv_wait_time_ns += (t_recv_end.tv_sec - t_recv_start.tv_sec) * 1000000000 +
						       (t_recv_end.tv_nsec - t_recv_start.tv_nsec);
			if (ret < 0) {
				if (flags == MSG_DONTWAIT && (errno == EAGAIN || errno == EINTR)) {
					bulk_stats.recv_would_block++;
					return BULK_STREAM_WOULD_BLOCK;
				}
				pr_perror("Error reading header from page server");
				return -1;
			}
			bulk_stats.recv_bytes += ret;
			ar->rb += ret;
		}

		if (ar->rb == sizeof(ar->pi)) {
			cmd = decode_ps_cmd(ar->pi.cmd);

				if (ar->pi.nr_pages == 0) {
					pr_info("Received end-of-transfer marker (cmd=%u dst_id=%lu)\n", cmd,
						(unsigned long)ar->pi.dst_id);
					bulk_stream_done = true;

					return BULK_STREAM_COMPLETE;
				}

			if (cmd == PS_IOV_ADD_F_COMPRESS) {
				ar->compress_state = COMPRESS_STATE_READING_SIZE;
				ar->compressed_size = 0;
				ar->compressed_rb = 0;
			} else {
				ar->compress_state = COMPRESS_STATE_READING_UNCOMPRESSED;
				ar->goal = sizeof(ar->pi) + ar->pi.nr_pages * PAGE_SIZE;
			}
		}

		return BULK_STREAM_PROGRESS;
	}

	/* Reading compressed size */
	if (ar->compress_state == COMPRESS_STATE_READING_SIZE) {
		struct timespec t_recv_start, t_recv_end;

		need = sizeof(ar->compressed_size) - ar->compressed_rb;
		buf = ((char *)&ar->compressed_size) + ar->compressed_rb;

		clock_gettime(CLOCK_MONOTONIC, &t_recv_start);
		bulk_stats.recv_calls++;
		ret = __recv(page_server_sk, buf, need, flags);
		clock_gettime(CLOCK_MONOTONIC, &t_recv_end);
		bulk_stats.recv_wait_time_ns += (t_recv_end.tv_sec - t_recv_start.tv_sec) * 1000000000 +
					       (t_recv_end.tv_nsec - t_recv_start.tv_nsec);
		if (ret < 0) {
			if (flags == MSG_DONTWAIT && (errno == EAGAIN || errno == EINTR)) {
				bulk_stats.recv_would_block++;
				return BULK_STREAM_WOULD_BLOCK;
			}
			pr_perror("Error reading compressed size");
			return -1;
		}
		bulk_stats.recv_bytes += ret;
		ar->compressed_rb += ret;

		if (ar->compressed_rb == sizeof(ar->compressed_size)) {
			if (ar->compressed_size <= 0 || ar->compressed_size > LZ4_compressBound(PAGE_SIZE)) {
				pr_err("Invalid compressed size: %d\n", ar->compressed_size);
				return -1;
			}

			ar->compressed_buf = xmalloc(ar->compressed_size);
			if (!ar->compressed_buf) {
				pr_err("Failed to allocate compressed buffer\n");
				return -1;
			}

			ar->compressed_rb = 0;
			ar->compress_state = COMPRESS_STATE_READING_COMPRESSED;
		}

		return BULK_STREAM_PROGRESS;
	}

	/* Reading compressed data */
	if (ar->compress_state == COMPRESS_STATE_READING_COMPRESSED) {
		struct timespec t_recv_start, t_recv_end;

		need = ar->compressed_size - ar->compressed_rb;
		buf = ar->compressed_buf + ar->compressed_rb;

		clock_gettime(CLOCK_MONOTONIC, &t_recv_start);
		bulk_stats.recv_calls++;
		ret = __recv(page_server_sk, buf, need, flags);
		clock_gettime(CLOCK_MONOTONIC, &t_recv_end);
		bulk_stats.recv_wait_time_ns += (t_recv_end.tv_sec - t_recv_start.tv_sec) * 1000000000 +
					       (t_recv_end.tv_nsec - t_recv_start.tv_nsec);
		if (ret < 0) {
			if (flags == MSG_DONTWAIT && (errno == EAGAIN || errno == EINTR)) {
				bulk_stats.recv_would_block++;
				return BULK_STREAM_WOULD_BLOCK;
			}
			pr_perror("Error reading compressed data");
			xfree(ar->compressed_buf);
			ar->compressed_buf = NULL;
			return -1;
		}
		bulk_stats.recv_bytes += ret;
		ar->compressed_rb += ret;

		if (ar->compressed_rb == ar->compressed_size) {
			int decomp_ret;
			struct timespec t1, t2;

			clock_gettime(CLOCK_MONOTONIC, &t1);
			decomp_ret = LZ4_decompress_safe(ar->compressed_buf, ar->pages, ar->compressed_size,
							 PAGE_SIZE);
			clock_gettime(CLOCK_MONOTONIC, &t2);
			bulk_stats.decompress_calls++;
			bulk_stats.decompress_time_ns +=
				(t2.tv_sec - t1.tv_sec) * 1000000000 + (t2.tv_nsec - t1.tv_nsec);
			xfree(ar->compressed_buf);
			ar->compressed_buf = NULL;

			if (decomp_ret != PAGE_SIZE) {
				pr_err("LZ4 decompression failed: expected %lu, got %d\n", PAGE_SIZE, decomp_ret);
				return -1;
			}

			bulk_stats.callback_calls++;
			bulk_stats.pages_completed++;
			ret = ar->complete((int)ar->pi.dst_id, (unsigned long)ar->pi.vaddr, (int)ar->pi.nr_pages,
					   ar->priv);
			if (ret < 0)
				return ret;

			ar->rb = 0;
			ar->goal = 0;
			ar->compress_state = COMPRESS_STATE_READING_HEADER;
			ar->compressed_size = 0;
			ar->compressed_rb = 0;
		}

		return BULK_STREAM_PROGRESS;
	}

	/* Reading uncompressed page data */
	if (ar->compress_state == COMPRESS_STATE_READING_UNCOMPRESSED) {
		struct timespec t_recv_start, t_recv_end;

		buf = ar->pages + (ar->rb - sizeof(ar->pi));
		need = ar->goal - ar->rb;

		clock_gettime(CLOCK_MONOTONIC, &t_recv_start);
		bulk_stats.recv_calls++;
		ret = __recv(page_server_sk, buf, need, flags);
		clock_gettime(CLOCK_MONOTONIC, &t_recv_end);
		bulk_stats.recv_wait_time_ns += (t_recv_end.tv_sec - t_recv_start.tv_sec) * 1000000000 +
					       (t_recv_end.tv_nsec - t_recv_start.tv_nsec);
		if (ret < 0) {
			if (flags == MSG_DONTWAIT && (errno == EAGAIN || errno == EINTR)) {
				bulk_stats.recv_would_block++;
				return BULK_STREAM_WOULD_BLOCK;
			}
			pr_perror("Error reading uncompressed page data");
			return -1;
		}
		bulk_stats.recv_bytes += ret;
		ar->rb += ret;

		if (ar->rb == ar->goal) {
			bulk_stats.callback_calls++;
			bulk_stats.pages_completed++;
			ret = ar->complete((int)ar->pi.dst_id, (unsigned long)ar->pi.vaddr, (int)ar->pi.nr_pages,
					   ar->priv);
			if (ret < 0)
				return ret;

			ar->rb = 0;
			ar->goal = 0;
			ar->compress_state = COMPRESS_STATE_READING_HEADER;
		}

		return BULK_STREAM_PROGRESS;
	}

	return BULK_STREAM_PROGRESS;
}

/* Bulk stream statistics */


static void check_and_print_bulk_stats(void)
{
	time_t now = time(NULL);
	
	if (now - bulk_stats.last_print_time >= 1) {
		struct timespec ts;
		struct tm *tm;
		clock_gettime(CLOCK_REALTIME, &ts);
		tm = localtime(&ts.tv_sec);
		pr_debug("[BULK_RECV_STATS] [%02d:%02d:%02d.%03ld] recv=%lu block=%lu bytes=%lu recv_wait_ns=%lu pages=%lu decomp=%lu decomp_ns=%lu cb=%lu\n",
			tm->tm_hour, tm->tm_min, tm->tm_sec, ts.tv_nsec / 1000000,
			bulk_stats.recv_calls,
			bulk_stats.recv_would_block,
			bulk_stats.recv_bytes,
			bulk_stats.recv_wait_time_ns,
			bulk_stats.pages_completed,
			bulk_stats.decompress_calls,
			bulk_stats.decompress_time_ns,
			bulk_stats.callback_calls);
		
		memset(&bulk_stats, 0, sizeof(bulk_stats));
		bulk_stats.last_print_time = now;
	}
}

static int page_server_async_read_bulk(struct epoll_rfd *f)
{
	struct ps_async_read *ar;
	int ret;
	pr_debug("page_server_async_read_bulk\n");
	
	check_and_print_bulk_stats();

	if (list_empty(&async_reads)) {
		if (opts.cow_dump && bulk_stream_done)
			return 0;
		pr_err("Bulk async read with empty queue\n");
		return -1;
	}

	ar = list_first_entry(&async_reads, struct ps_async_read, l);
	ret = page_server_read_bulk_stream(ar, MSG_DONTWAIT);

	if (ret == BULK_STREAM_COMPLETE) {
		/* End marker - cleanup stream reader */
		list_del(&ar->l);
		xfree(ar);
		return 0;
	}
	if (ret < 0)
		return -1;

	/* ret == BULK_STREAM_WOULD_BLOCK or BULK_STREAM_PROGRESS - keep going */
	return 0;
}

int page_server_start_async_read_bulk(void *buf, unsigned long nr_pages, 
					      ps_async_read_complete complete, void *priv)
{
	struct ps_async_read *ar;

	/* In bulk mode, only create reader once - it processes continuous stream */
	if (!list_empty(&async_reads)) {
		/* Already have a stream reader */
		return 0;
	}

	ar = xmalloc(sizeof(*ar));
	if (ar == NULL)
		return -1;

	ar->pages = buf;
	ar->rb = 0;
	ar->goal = 0; /* Will be set when header arrives */
	ar->nr_pages = nr_pages; /* Max buffer size */
	ar->complete = complete;
	ar->priv = priv;
	
	/* Initialize compression state */
	ar->compress_state = COMPRESS_STATE_READING_HEADER;
	ar->compressed_size = 0;
	ar->compressed_rb = 0;
	ar->compressed_buf = NULL;
	
	list_add_tail(&ar->l, &async_reads);
	return 0;
}

/*
 * There are two possible event types we need to handle:
 * - page info is available as a reply to request_remote_page
 * - page data is available, and it follows page info we've just received
 * Since the on dump side communications are completely synchronous,
 * we can return to epoll right after the reception of page info and
 * for sure the next time socket event will occur we'll get page data
 * related to info we've just received
 */
static int page_server_read(struct ps_async_read *ar, int flags)
{
	int ret, need;
	void *buf;

	if (ar->rb < sizeof(ar->pi)) {
		/* Header */
		buf = ((void *)&ar->pi) + ar->rb;
		need = sizeof(ar->pi) - ar->rb;
	} else {
		/* page-serer may return less pages than we asked for */
		if (ar->pi.nr_pages < ar->nr_pages)
			async_read_set_goal(ar, ar->pi.nr_pages);
		/* Page(s) data itself */
		buf = ar->pages + (ar->rb - sizeof(ar->pi));
		need = ar->goal - ar->rb;
	}

	ret = __recv(page_server_sk, buf, need, flags);
	if (ret < 0) {
		if (flags == MSG_DONTWAIT && (errno == EAGAIN || errno == EINTR)) {
			ret = 0;
		} else {
			pr_perror("Error reading data from page server");
			return -1;
		}
	}

	ar->rb += ret;
	if (ar->rb < ar->goal)
		return 1;

	/*
	 * IO complete -- notify the caller and drop the request
	 */
	BUG_ON(ar->rb > ar->goal);
	return ar->complete((int)ar->pi.dst_id, (unsigned long)ar->pi.vaddr, (int)ar->pi.nr_pages, ar->priv);
}

static int page_server_async_read(struct epoll_rfd *f)
{
	struct ps_async_read *ar;
	int ret;

	BUG_ON(list_empty(&async_reads));
	ar = list_first_entry(&async_reads, struct ps_async_read, l);
	ret = page_server_read(ar, MSG_DONTWAIT);

	if (ret > 0)
		return 0;
	if (!ret) {
		list_del(&ar->l);
		xfree(ar);
	}

	return ret;
}

static int page_server_hangup_event(struct epoll_rfd *rfd)
{
	if (opts.cow_dump && bulk_stream_done) {
		pr_info("Page server closed connection after bulk transfer\n");
		return 0;
	}
	pr_err("Remote side closed connection\n");
	return -1;
}

static struct epoll_rfd ps_rfd;

int connect_to_page_server_to_recv(int epfd)
{
	if (connect_to_page_server())
		return -1;
	bulk_stream_done = false;

	ps_rfd.fd = page_server_sk;
	/* Use bulk stream reader in bulk mode, regular reader in on-demand mode */
	if (opts.cow_dump)
		ps_rfd.read_event = page_server_async_read_bulk;
	else
		ps_rfd.read_event = page_server_async_read;
	ps_rfd.hangup_event = page_server_hangup_event;

	return epoll_add_rfd(epfd, &ps_rfd);
}

int request_remote_pages(unsigned long img_id, unsigned long addr, unsigned long nr_pages)
{
	struct page_server_iov pi = {
		.cmd = PS_IOV_GET,
		.nr_pages = nr_pages,
		.vaddr = addr,
		.dst_id = img_id,
	};

	/* XXX: why MSG_DONTWAIT here? */
	if (send_psi_flags(page_server_sk, &pi, MSG_DONTWAIT))
		return -1;

	tcp_nodelay(page_server_sk, true);
	return 0;
}

int request_all_remote_pages(unsigned long img_id)
{
	struct page_server_iov pi = {
		.cmd = PS_IOV_GET_ALL,
		.nr_pages = 0,  /* Not used in batch mode */
		.vaddr = 0,     /* Not used in batch mode */
		.dst_id = img_id,
	};

	pr_info("Requesting all pages for img_id=%lu in batch mode\n", img_id);

	if (send_psi_flags(page_server_sk, &pi, MSG_DONTWAIT))
		return -1;

	tcp_nodelay(page_server_sk, true);
	return 0;
}

static int page_server_start_sync_read(void *buf, unsigned long nr, ps_async_read_complete complete, void *priv)
{
	struct ps_async_read ar;
	int ret = 1;

	init_ps_async_read(&ar, buf, nr, complete, priv);
	while (ret == 1)
		ret = page_server_read(&ar, MSG_WAITALL);
	return ret;
}

int page_server_start_read(void *buf, unsigned long nr, ps_async_read_complete complete, void *priv, unsigned flags)
{
	/* In bulk mode, use continuous stream reader */
	pr_debug("page_server_start_read\n");

	if (opts.cow_dump) {
		if (flags & PR_ASYNC)
			return page_server_start_async_read_bulk(buf, nr, complete, priv);
		else {
			pr_err("Bulk mode doesn't support synchronous reads\n");
			return -1;
		}
	}
	
	/* On-demand mode: traditional request/response */
	if (flags & PR_ASYNC)
		return page_server_start_async_read(buf, nr, complete, priv);
	else
		return page_server_start_sync_read(buf, nr, complete, priv);
}
