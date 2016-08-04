#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/falloc.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "cr_options.h"
#include "servicefd.h"
#include "image.h"
#include "page-xfer.h"
#include "page-pipe.h"
#include "util.h"
#include "protobuf.h"
#include "images/pagemap.pb-c.h"

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

#define PS_IOV_FLUSH		0x1023
#define PS_IOV_FLUSH_N_CLOSE	0x1024

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

static inline int send_iov(int sk, u32 cmd, u64 dst_id, struct iovec *iov)
{
	u64 vaddr = encode_pointer(iov->iov_base);
	u32 nr_pages = iov->iov_len / PAGE_SIZE;

	return send_psi(sk, cmd, nr_pages, vaddr, dst_id);
}

/* page-server xfer */
static int write_pagemap_to_server(struct page_xfer *xfer,
		struct iovec *iov)
{
	return send_iov(xfer->sk, PS_IOV_ADD, xfer->dst_id, iov);
}

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

static int write_hole_to_server(struct page_xfer *xfer, struct iovec *iov)
{
	return send_iov(xfer->sk, PS_IOV_HOLE, xfer->dst_id, iov);
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
	xfer->write_hole = write_hole_to_server;
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
static int write_pagemap_loc(struct page_xfer *xfer,
		struct iovec *iov)
{
	int ret;
	PagemapEntry pe = PAGEMAP_ENTRY__INIT;

	iovec2pagemap(iov, &pe);
	if (opts.auto_dedup && xfer->parent != NULL) {
		ret = dedup_one_iovec(xfer->parent, iov);
		if (ret == -1) {
			pr_perror("Auto-deduplication failed");
			return ret;
		}
	}
	return pb_write_one(xfer->pmi, &pe, PB_PAGEMAP);
}

static int write_pages_loc(struct page_xfer *xfer,
		int p, unsigned long len)
{
	ssize_t ret;

	ret = splice(p, NULL, img_raw_fd(xfer->pi), NULL, len, SPLICE_F_MOVE);
	if (ret == -1) {
		pr_perror("Unable to spice data");
		return -1;
	}
	if (ret != len) {
		pr_err("Only %zu of %lu bytes have been spliced\n", ret, len);
		return -1;
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
		struct iovec piov;
		unsigned long pend;

		ret = p->seek_page(p, off, true);
		if (ret <= 0 || !p->pe)
			return -1;

		pagemap2iovec(p->pe, &piov);
		pr_debug("\tFound %p/%zu\n", piov.iov_base, piov.iov_len);

		/*
		 * The pagemap entry in parent may heppen to be
		 * shorter, than the hole we write. In this case
		 * we should go ahead and check the remainder.
		 */

		pend = (unsigned long)piov.iov_base + piov.iov_len;
		if (end <= pend)
			return 0;

		pr_debug("\t\tcontinue on %lx\n", pend);
		off = pend;
	}
}

static int write_pagehole_loc(struct page_xfer *xfer, struct iovec *iov)
{
	PagemapEntry pe = PAGEMAP_ENTRY__INIT;

	if (xfer->parent != NULL) {
		int ret;

		ret = check_pagehole_in_parent(xfer->parent, iov);
		if (ret) {
			pr_err("Hole %p/%zu not found in parent\n",
					iov->iov_base, iov->iov_len);
			return -1;
		}
	}

	iovec2pagemap(iov, &pe);
	pe.has_in_parent = true;
	pe.in_parent = true;

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
	if (fd_type == CR_FD_PAGEMAP) {
		int ret;
		int pfd;

		pfd = openat(get_service_fd(IMG_FD_OFF), CR_PARENT_LINK, O_RDONLY);
		if (pfd < 0 && errno == ENOENT)
			goto out;

		xfer->parent = xmalloc(sizeof(*xfer->parent));
		if (!xfer->parent) {
			close(pfd);
			return -1;
		}

		ret = open_page_read_at(pfd, id, xfer->parent, PR_TASK);
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
	xfer->write_hole = write_pagehole_loc;
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
		struct iovec *hole, unsigned long off)
{
	BUG_ON(hole->iov_base < (void *)off);
	hole->iov_base -= off;
	pr_debug("\th %p [%u]\n", hole->iov_base,
			(unsigned int)(hole->iov_len / PAGE_SIZE));

	if (xfer->write_hole(xfer, hole))
		return -1;

	return 0;
}

static struct iovec get_iov(struct iovec *iovs, unsigned int n)
{
	return iovs[n];
}

static int dump_holes(struct page_xfer *xfer, struct page_pipe *pp,
		      unsigned int *cur_hole, void *limit, unsigned long off)
{
	int ret;

	for (; *cur_hole < pp->free_hole ; (*cur_hole)++) {
		struct iovec hole = get_iov(pp->holes, *cur_hole);

		if (limit && hole.iov_base >= limit)
			break;

		ret = page_xfer_dump_hole(xfer, &hole, off);
		if (ret)
			return ret;
	}

	return 0;
}

int page_xfer_dump_pages(struct page_xfer *xfer, struct page_pipe *pp,
		unsigned long off)
{
	struct page_pipe_buf *ppb;
	unsigned int cur_hole = 0;
	int ret;

	pr_debug("Transferring pages:\n");

	list_for_each_entry(ppb, &pp->bufs, l) {
		unsigned int i;

		pr_debug("\tbuf %d/%d\n", ppb->pages_in, ppb->nr_segs);

		for (i = 0; i < ppb->nr_segs; i++) {
			struct iovec iov = get_iov(ppb->iov, i);

			ret = dump_holes(xfer, pp, &cur_hole, iov.iov_base, off);
			if (ret)
				return ret;

			BUG_ON(iov.iov_base < (void *)off);
			iov.iov_base -= off;
			pr_debug("\tp %p [%u]\n", iov.iov_base,
					(unsigned int)(iov.iov_len / PAGE_SIZE));

			if (xfer->write_pagemap(xfer, &iov))
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

static int page_server_add(int sk, struct page_server_iov *pi)
{
	size_t len;
	struct page_xfer *lxfer = &cxfer.loc_xfer;
	struct iovec iov;

	pr_debug("Adding %"PRIx64"/%u\n", pi->vaddr, pi->nr_pages);

	if (prep_loc_xfer(pi))
		return -1;

	psi2iovec(pi, &iov);
	if (lxfer->write_pagemap(lxfer, &iov))
		return -1;

	len = iov.iov_len;
	while (len > 0) {
		ssize_t chunk;

		chunk = len;
		if (chunk > cxfer.pipe_size)
			chunk = cxfer.pipe_size;

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

static int page_server_hole(int sk, struct page_server_iov *pi)
{
	struct page_xfer *lxfer = &cxfer.loc_xfer;
	struct iovec iov;

	pr_debug("Adding %"PRIx64"/%u hole\n", pi->vaddr, pi->nr_pages);

	if (prep_loc_xfer(pi))
		return -1;

	psi2iovec(pi, &iov);
	if (lxfer->write_hole(lxfer, &iov))
		return -1;

	return 0;
}

static int page_server_serve(int sk)
{
	int ret = -1;
	bool flushed = false;

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

	while (1) {
		struct page_server_iov pi;

		ret = recv(sk, &pi, sizeof(pi), MSG_WAITALL);
		if (!ret)
			break;

		if (ret != sizeof(pi)) {
			pr_perror("Can't read pagemap from socket");
			ret = -1;
			break;
		}

		flushed = false;

		switch (pi.cmd) {
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
			ret = page_server_add(sk, &pi);
			break;
		case PS_IOV_HOLE:
			ret = page_server_hole(sk, &pi);
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

int cr_page_server(bool daemon_mode, int cfd)
{
	int ask = -1;
	int sk = -1;
	int ret;

	up_page_ids_base();

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
		return ret;

	if (ask >= 0)
		ret = page_server_serve(ask);

	if (daemon_mode)
		exit(ret);

	return ret;
}

int connect_to_page_server(void)
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
