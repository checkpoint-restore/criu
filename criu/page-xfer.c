#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/falloc.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

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

static int page_server_sk = -1;

struct page_server_iov {
	u32	cmd;
	u32	nr_pages;
	u64	vaddr;
	u64	dst_id;
};

static void psi2iovec(struct page_server_iov *ps, struct iovec *iov)
{
	iov->iov_base = decode_pointer(ps->vaddr);
	iov->iov_len = ps->nr_pages * PAGE_SIZE;
}

#define PS_IOV_ADD	1
#define PS_IOV_HOLE	2
#define PS_IOV_OPEN	3
#define PS_IOV_OPEN2	4
#define PS_IOV_PARENT	5
#define PS_IOV_ZERO	6
#define PS_IOV_LAZY	7
#define PS_IOV_GET	8

#define PS_IOV_FLUSH		0x1023
#define PS_IOV_FLUSH_N_CLOSE	0x1024

#define PS_CMD_BITS	16
#define PS_CMD_MASK	((1 << PS_CMD_BITS) - 1)

#define PS_TYPE_BITS	8
#define PS_TYPE_MASK	((1 << PS_TYPE_BITS) - 1)

static inline u64 encode_pm_id(int type, long id)
{
	return ((u64)id) << PS_TYPE_BITS | type;
}

static int decode_pm_type(u64 dst_id)
{
	return dst_id & PS_TYPE_MASK;
}

static long decode_pm_id(u64 dst_id)
{
	return (long)(dst_id >> PS_TYPE_BITS);
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

static inline int send_psi(int sk, u32 cmd, u32 nr_pages, u64 vaddr, u64 dst_id)
{
	struct page_server_iov pi = {
		.cmd		= cmd,
		.nr_pages	= nr_pages,
		.vaddr		= vaddr,
		.dst_id		= dst_id,
	};

	if (write(sk, &pi, sizeof(pi)) != sizeof(pi)) {
		pr_perror("Can't write PSI %d to server", cmd);
		return -1;
	}

	return 0;
}

/* page-server xfer */
static int write_pages_to_server(struct page_xfer *xfer,
		int p, unsigned long len)
{
	pr_debug("Splicing %lu bytes / %lu pages into socket\n", len, len / PAGE_SIZE);

	if (splice(p, NULL, xfer->sk, NULL, len, SPLICE_F_MOVE) != len) {
		pr_perror("Can't write pages to socket");
		return -1;
	}

	return 0;
}

static int write_pagemap_to_server(struct page_xfer *xfer, struct iovec *iov, u32 flags)
{
	u32 cmd = 0;

	if (flags & PE_PRESENT)
		cmd = encode_ps_cmd(PS_IOV_ADD, flags);
	else if (flags & PE_PARENT)
		cmd = PS_IOV_HOLE;
	else if (flags & PE_LAZY)
		cmd = PS_IOV_LAZY;
	else
		BUG();

	return send_psi(xfer->sk, cmd,
			iov->iov_len / PAGE_SIZE, encode_pointer(iov->iov_base),
			xfer->dst_id);
}

static void close_server_xfer(struct page_xfer *xfer)
{
	xfer->sk = -1;
}

static int open_page_server_xfer(struct page_xfer *xfer, int fd_type, long id)
{
	char has_parent;

	xfer->sk = page_server_sk;
	xfer->write_pagemap = write_pagemap_to_server;
	xfer->write_pages = write_pages_to_server;
	xfer->close = close_server_xfer;
	xfer->dst_id = encode_pm_id(fd_type, id);
	xfer->parent = NULL;

	if (send_psi(xfer->sk, PS_IOV_OPEN2, 0, 0, xfer->dst_id)) {
		pr_perror("Can't write to page server");
		return -1;
	}

	/* Push the command NOW */
	tcp_nodelay(xfer->sk, true);

	if (read(xfer->sk, &has_parent, 1) != 1) {
		pr_perror("The page server doesn't answer");
		return -1;
	}

	if (has_parent)
		xfer->parent = (void *) 1; /* This is required for generate_iovs() */

	return 0;
}

/* local xfer */
static int write_pages_loc(struct page_xfer *xfer,
		int p, unsigned long len)
{
	ssize_t ret;
	ssize_t curr = 0;

	while (1) {
		ret = splice(p, NULL, img_raw_fd(xfer->pi), NULL, len, SPLICE_F_MOVE);
		if (ret == -1) {
			pr_perror("Unable to spice data");
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

	pr_debug("Checking %p/%zu hole\n", iov->iov_base, iov->iov_len);
	off = (unsigned long)iov->iov_base;
	end = off + iov->iov_len;
	while (1) {
		unsigned long pend;

		ret = p->seek_pagemap(p, off);
		if (ret <= 0 || !p->pe) {
			pr_err("Missing %lx in parent pagemap\n", off);
			return -1;
		}

		pr_debug("\tFound %"PRIx64"/%lu\n", p->pe->vaddr, pagemap_len(p->pe));

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

	if (flags & PE_PRESENT) {
		if (opts.auto_dedup && xfer->parent != NULL) {
			ret = dedup_one_iovec(xfer->parent, pe.vaddr,
					      pagemap_len(&pe));
			if (ret == -1) {
				pr_perror("Auto-deduplication failed");
				return ret;
			}
		}
	} else if (flags & PE_PARENT) {
		if (xfer->parent != NULL) {
			ret = check_pagehole_in_parent(xfer->parent, iov);
			if (ret) {
				pr_err("Hole %p/%zu not found in parent\n",
				       iov->iov_base, iov->iov_len);
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

static int open_page_local_xfer(struct page_xfer *xfer, int fd_type, long id)
{
	xfer->pmi = open_image(fd_type, O_DUMP, id);
	if (!xfer->pmi)
		return -1;

	xfer->pi = open_pages_image(O_DUMP, xfer->pmi);
	if (!xfer->pi) {
		close_image(xfer->pmi);
		return -1;
	}

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

		pfd = openat(get_service_fd(IMG_FD_OFF), CR_PARENT_LINK, O_RDONLY);
		if (pfd < 0 && errno == ENOENT)
			goto out;

		xfer->parent = xmalloc(sizeof(*xfer->parent));
		if (!xfer->parent) {
			close(pfd);
			return -1;
		}

		ret = open_page_read_at(pfd, id, xfer->parent, pr_flags);
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
}

int open_page_xfer(struct page_xfer *xfer, int fd_type, long id)
{
	if (opts.use_page_server)
		return open_page_server_xfer(xfer, fd_type, id);
	else
		return open_page_local_xfer(xfer, fd_type, id);
}

static int page_xfer_dump_hole(struct page_xfer *xfer,
			       struct iovec *hole, unsigned long off, u32 flags)
{
	BUG_ON(hole->iov_base < (void *)off);
	hole->iov_base -= off;
	pr_debug("\th %p [%u]\n", hole->iov_base,
			(unsigned int)(hole->iov_len / PAGE_SIZE));

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

static int dump_holes(struct page_xfer *xfer, struct page_pipe *pp,
		      unsigned int *cur_hole, void *limit, unsigned long off)
{
	int ret;

	for (; *cur_hole < pp->free_hole ; (*cur_hole)++) {
		struct iovec hole = pp->holes[*cur_hole];
		u32 hole_flags;

		if (limit && hole.iov_base >= limit)
			break;

		hole_flags = get_hole_flags(pp, *cur_hole);
		ret = page_xfer_dump_hole(xfer, &hole, off, hole_flags);
		if (ret)
			return ret;
	}

	return 0;
}

int page_xfer_dump_pages(struct page_xfer *xfer, struct page_pipe *pp,
			 unsigned long off, bool dump_lazy)
{
	struct page_pipe_buf *ppb;
	unsigned int cur_hole = 0;
	int ret;

	pr_debug("Transferring pages:\n");

	list_for_each_entry(ppb, &pp->bufs, l) {
		unsigned int i;

		pr_debug("\tbuf %d/%d\n", ppb->pages_in, ppb->nr_segs);

		for (i = 0; i < ppb->nr_segs; i++) {
			struct iovec iov = ppb->iov[i];
			u32 flags = PE_PRESENT;

			ret = dump_holes(xfer, pp, &cur_hole, iov.iov_base, off);
			if (ret)
				return ret;

			BUG_ON(iov.iov_base < (void *)off);
			iov.iov_base -= off;
			pr_debug("\tp %p [%u]\n", iov.iov_base,
					(unsigned int)(iov.iov_len / PAGE_SIZE));

			if (ppb->flags & PPB_LAZY) {
				if (!dump_lazy) {
					if (xfer->write_pagemap(xfer, &iov, PE_LAZY))
						return -1;
					continue;
				} else {
					flags |= PE_LAZY;
				}
			}

			if (xfer->write_pagemap(xfer, &iov, flags))
				return -1;
			if (xfer->write_pages(xfer, ppb->p[0], iov.iov_len))
				return -1;
		}
	}

	return dump_holes(xfer, pp, &cur_hole, NULL, off);
}

/*
 * Return:
 *	 1 - if a parent image exists
 *	 0 - if a parent image doesn't exist
 *	-1 - in error cases
 */
int check_parent_local_xfer(int fd_type, int id)
{
	char path[PATH_MAX];
	struct stat st;
	int ret, pfd;

	pfd = openat(get_service_fd(IMG_FD_OFF), CR_PARENT_LINK, O_RDONLY);
	if (pfd < 0 && errno == ENOENT)
		return 0;

	snprintf(path, sizeof(path), imgset_template[fd_type].fmt, id);
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
	long id;

	type = decode_pm_type(pi->dst_id);
	id = decode_pm_id(pi->dst_id);

	ret = check_parent_local_xfer(type, id);
	if (ret < 0)
		return -1;

	if (write(sk, &ret, sizeof(ret)) != sizeof(ret)) {
		pr_perror("Unable to send response");
		return -1;
	}

	return 0;
}

static int check_parent_server_xfer(int fd_type, long id)
{
	struct page_server_iov pi = {};
	int has_parent;

	pi.cmd = PS_IOV_PARENT;
	pi.dst_id = encode_pm_id(fd_type, id);

	if (write(page_server_sk, &pi, sizeof(pi)) != sizeof(pi)) {
		pr_perror("Can't write to page server");
		return -1;
	}

	tcp_nodelay(page_server_sk, true);

	if (read(page_server_sk, &has_parent, sizeof(int)) != sizeof(int)) {
		pr_perror("The page server doesn't answer");
		return -1;
	}

	return has_parent;
}

int check_parent_page_xfer(int fd_type, long id)
{
	if (opts.use_page_server)
		return check_parent_server_xfer(fd_type, id);
	else
		return check_parent_local_xfer(fd_type, id);
}

struct page_xfer_job {
	u64	dst_id;
	int	p[2];
	unsigned pipe_size;
	struct page_xfer loc_xfer;
};

static struct page_xfer_job cxfer = {
	.dst_id = ~0,
};

static void page_server_close(void)
{
	if (cxfer.dst_id != ~0)
		cxfer.loc_xfer.close(&cxfer.loc_xfer);
}

static int page_server_open(int sk, struct page_server_iov *pi)
{
	int type;
	long id;

	type = decode_pm_type(pi->dst_id);
	id = decode_pm_id(pi->dst_id);
	pr_info("Opening %d/%ld\n", type, id);

	page_server_close();

	if (open_page_local_xfer(&cxfer.loc_xfer, type, id))
		return -1;

	cxfer.dst_id = pi->dst_id;

	if (sk >= 0) {
		char has_parent = !!cxfer.loc_xfer.parent;

		if (write(sk, &has_parent, 1) != 1) {
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

static int page_server_add(int sk, struct page_server_iov *pi, u32 flags)
{
	size_t len;
	struct page_xfer *lxfer = &cxfer.loc_xfer;
	struct iovec iov;

	pr_debug("Adding %"PRIx64"/%u\n", pi->vaddr, pi->nr_pages);

	if (prep_loc_xfer(pi))
		return -1;

	psi2iovec(pi, &iov);
	if (lxfer->write_pagemap(lxfer, &iov, flags))
		return -1;

	if (!(flags & PE_PRESENT))
		return 0;

	len = iov.iov_len;
	while (len > 0) {
		ssize_t chunk;

		chunk = len;
		if (chunk > cxfer.pipe_size)
			chunk = cxfer.pipe_size;

		/*
		 * Splicing into a pipe may end up blocking if pipe is "full",
		 * and we need the SPLICE_F_NONBLOCK flag here. At the same time
		 * splcing from UNIX socket with this flag aborts splice with
		 * the EAGAIN if there's no data in it (TCP looks at the socket
		 * O_NONBLOCK flag _only_ and waits for data), so before doing
		 * the non-blocking splice we need to explicitly wait.
		 */

		if (sk_wait_data(sk) < 0) {
			pr_perror("Can't poll socket");
			return -1;
		}

		chunk = splice(sk, NULL, cxfer.p[1], NULL, chunk, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
		if (chunk < 0) {
			pr_perror("Can't read from socket");
			return -1;
		}

		if (lxfer->write_pages(lxfer, cxfer.p[0], chunk))
			return -1;

		len -= chunk;
	}

	return 0;
}

static bool can_send_pages(struct page_pipe_buf *ppb, struct iovec *iov,
			   struct page_server_iov *pi)
{
	unsigned long len = pi->nr_pages * PAGE_SIZE;

	if (!(ppb->flags & PPB_LAZY)) {
		pr_err("Requested pages are not lazy\n");
		return false;
	}

	if (iov->iov_len != len) {
		pr_err("IOV len %zu does not match requested %lu\n",
		       iov->iov_len, len);
		return false;
	}

	if(pi->vaddr != encode_pointer(iov->iov_base)) {
		pr_err("IOV start %p does not match requested addr %"PRIx64"\n",
		       iov->iov_base, pi->vaddr);
		return false;
	}

	return true;
}

static int page_server_get_pages(int sk, struct page_server_iov *pi)
{
	struct pstree_item *item;
	struct page_pipe *pp;
	struct page_pipe_buf *ppb;
	struct iovec *iov;
	int ret;

	item = pstree_item_by_virt(pi->dst_id);
	pp = dmpi(item)->mem_pp;

	ret = page_pipe_split(pp, pi->vaddr, &pi->nr_pages);
	if (ret)
		return ret;

	if (pi->nr_pages == 0) {
		/* no iovs found means we've hit a zero page */
		pr_debug("no iovs found, zero pages\n");
		return send_psi(sk, PS_IOV_ZERO, 0, 0, 0);
	}

	ppb = list_first_entry(&pp->bufs, struct page_pipe_buf, l);
	iov = &ppb->iov[0];

	if (!can_send_pages(ppb, iov, pi))
		return -1;

	if (send_psi(sk, PS_IOV_ADD, pi->nr_pages, pi->vaddr, pi->dst_id))
		return -1;

	ret = splice(ppb->p[0], NULL, sk, NULL, iov->iov_len, SPLICE_F_MOVE);
	if (ret != iov->iov_len)
		return -1;

	tcp_nodelay(sk, true);

	page_pipe_destroy_ppb(ppb);

	return 0;
}

static int page_server_serve(int sk)
{
	int ret = -1;
	bool flushed = false;

	if (!opts.lazy_pages) {
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
		tcp_cork(sk, true);
	}

	while (1) {
		struct page_server_iov pi;
		u32 cmd;

		ret = recv(sk, &pi, sizeof(pi), MSG_WAITALL);
		if (!ret)
			break;

		if (ret != sizeof(pi)) {
			pr_perror("Can't read pagemap from socket");
			ret = -1;
			break;
		}

		flushed = false;
		cmd = decode_ps_cmd(pi.cmd);

		switch (cmd) {
		case PS_IOV_OPEN:
			ret = page_server_open(-1, &pi);
			break;
		case PS_IOV_OPEN2:
			ret = page_server_open(sk, &pi);
			break;
		case PS_IOV_PARENT:
			ret = page_server_check_parent(sk, &pi);
			break;
		case PS_IOV_ADD:
			ret = page_server_add(sk, &pi, PE_PRESENT | decode_ps_flags(pi.cmd));
			break;
		case PS_IOV_HOLE:
			ret = page_server_add(sk, &pi, PE_PARENT);
			break;
		case PS_IOV_LAZY:
			ret = page_server_add(sk, &pi, PE_LAZY);
			break;
		case PS_IOV_FLUSH:
		case PS_IOV_FLUSH_N_CLOSE:
		{
			int32_t status = 0;

			ret = 0;

			/*
			 * An answer must be sent back to inform another side,
			 * that all data were received
			 */
			if (write(sk, &status, sizeof(status)) != sizeof(status)) {
				pr_perror("Can't send the final package");
				ret = -1;
			}

			flushed = true;
			break;
		}
		case PS_IOV_GET:
			flushed = true;
			ret = page_server_get_pages(sk, &pi);
			break;
		default:
			pr_err("Unknown command %u\n", pi.cmd);
			ret = -1;
			break;
		}

		if (ret || (pi.cmd == PS_IOV_FLUSH_N_CLOSE))
			break;
	}

	if (!ret && !flushed) {
		pr_err("The data were not flushed\n");
		ret = -1;
	}

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

			if (splice(img_raw_fd(pr->pi), NULL, ppb->p[1], NULL,
				   iov.iov_len, SPLICE_F_MOVE) != iov.iov_len) {
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
	int nr_pages = 0;

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
		return -1;
	}

	if (fill_page_pipe(&pr, *pp))
		return -1;

	return 0;
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

		if (page_pipe_from_pagemap(&pp, pi->pid->ns[0].virt)) {
			pr_err("%d: failed to open page-read\n", pi->pid->ns[0].virt);
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

	if (!opts.lazy_pages)
		up_page_ids_base();
	else if (!lazy_dump)
		if (page_server_init_send())
			return -1;

	if (opts.ps_socket != -1) {
		ret = 0;
		ask = opts.ps_socket;
		pr_info("Re-using ps socket %d\n", ask);
		goto no_server;
	}

	sk = setup_tcp_server("page");
	if (sk == -1)
		return -1;
no_server:
	ret = run_tcp_server(daemon_mode, &ask, cfd, sk);
	if (ret != 0)
		return ret > 0 ? 0 : -1;

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
		pr_info("Re-using ps socket %d\n", page_server_sk);
		goto out;
	}

	page_server_sk = setup_tcp_client(opts.addr);
	if (page_server_sk == -1)
		return -1;
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
	struct page_server_iov pi = { };
	int32_t status = -1;
	int ret = -1;

	if (!opts.use_page_server)
		return 0;

	if (page_server_sk == -1)
		return 0;

	pr_info("Disconnect from the page server %s:%u\n",
			opts.addr, (int)ntohs(opts.port));

	if (opts.ps_socket != -1)
		/*
		 * The socket might not get closed (held by
		 * the parent process) so we must order the
		 * page-server to terminate itself.
		 */
		pi.cmd = PS_IOV_FLUSH_N_CLOSE;
	else
		pi.cmd = PS_IOV_FLUSH;

	if (write(page_server_sk, &pi, sizeof(pi)) != sizeof(pi)) {
		pr_perror("Can't write the fini command to server");
		goto out;
	}

	if (read(page_server_sk, &status, sizeof(status)) != sizeof(status)) {
		pr_perror("The page server doesn't answer");
		goto out;
	}

	ret = 0;
out:
	close_safe(&page_server_sk);
	return ret ? : status;
}

struct ps_async_read {
	unsigned long rb; /* read bytes */
	unsigned long goal;

	struct page_server_iov pi;
	void *pages;

	ps_async_read_complete complete;
	void *priv;

	struct list_head l;
};

static LIST_HEAD(async_reads);

int page_server_start_async_read(void *buf, int nr_pages,
		ps_async_read_complete complete, void *priv)
{
	struct ps_async_read *ar;

	ar = xmalloc(sizeof(*ar));
	if (ar == NULL)
		return -1;

	ar->pages = buf;
	ar->rb = 0;
	ar->goal = sizeof(ar->pi) + nr_pages * PAGE_SIZE;
	ar->complete = complete;
	ar->priv = priv;

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
static int page_server_async_read(struct epoll_rfd *f)
{
	struct ps_async_read *ar;
	int ret, need;
	void *buf;

	BUG_ON(list_empty(&async_reads));
	ar = list_first_entry(&async_reads, struct ps_async_read, l);

	if (ar->rb < sizeof(ar->pi)) {
		/* Header */
		buf = ((void *)&ar->pi) + ar->rb;
		need = sizeof(ar->pi) - ar->rb;
	} else {
		/* Page(s) data itself */
		buf = ar->pages + (ar->rb - sizeof(ar->pi));
		need = ar->goal - ar->rb;
	}

	ret = recv(page_server_sk, buf, need, MSG_DONTWAIT);
	if (ret < 0) {
		pr_perror("Error reading async data from page server");
		return -1;
	}

	ar->rb += ret;
	if (ar->rb < ar->goal)
		return 0;

	/*
	 * IO complete -- notify the caller and drop the request
	 */
	BUG_ON(ar->rb > ar->goal);
	ret = ar->complete((int)ar->pi.dst_id, (unsigned long)ar->pi.vaddr,
				(int)ar->pi.nr_pages, ar->priv);

	list_del(&ar->l);
	xfree(ar);

	return ret;
}

static struct epoll_rfd ps_rfd;

int connect_to_page_server_to_recv(int epfd)
{
	if (connect_to_page_server())
		return -1;

	ps_rfd.fd = page_server_sk;
	ps_rfd.revent = page_server_async_read;

	return epoll_add_rfd(epfd, &ps_rfd);
}

int request_remote_pages(int pid, unsigned long addr, int nr_pages)
{
	struct page_server_iov pi = {
		.cmd		= PS_IOV_GET,
		.nr_pages	= nr_pages,
		.vaddr		= addr,
		.dst_id		= pid,
	};

	/* We cannot use send_psi here because we have to use MSG_DONTWAIT */
	if (send(page_server_sk, &pi, sizeof(pi), MSG_DONTWAIT) != sizeof(pi)) {
		pr_perror("Can't write PSI to server");
		return -1;
	}

	tcp_nodelay(page_server_sk, true);
	return 0;
}

int receive_remote_pages_info(int *nr_pages, unsigned long *addr, int *pid)
{
	struct page_server_iov pi;

	if (recv(page_server_sk, &pi, sizeof(pi), MSG_WAITALL) != sizeof(pi)) {
		pr_perror("Failed to receive page metadata");
		return -1;
	}

	if (pi.cmd == PS_IOV_ZERO)
		pr_warn("Unexpected ZERO page received for %d.%lx\n",
				(int)pi.dst_id, (unsigned long)pi.vaddr);

	*nr_pages = pi.nr_pages;
	*addr = pi.vaddr;
	*pid = pi.dst_id;

	return 0;
}

int receive_remote_pages(int len, void *buf)
{
	if (recv(page_server_sk, buf, len, MSG_WAITALL) != len) {
		pr_perror("Failed to receive page data");
		return -1;
	}

	return 0;
}
