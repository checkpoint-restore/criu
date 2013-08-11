#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "crtools.h"
#include "page-xfer.h"
#include "page-pipe.h"

#include "protobuf.h"
#include "protobuf/pagemap.pb-c.h"

struct page_server_iov {
	u32	cmd;
	u32	nr_pages;
	u64	vaddr;
	u64	dst_id;
};

#define PS_IOV_ADD	1
#define PS_IOV_HOLE	2
#define PS_IOV_OPEN	3

#define PS_IOV_FLUSH		0x1023

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

static int page_server_open(struct page_server_iov *pi)
{
	int type;
	long id;

	type = decode_pm_type(pi->dst_id);
	id = decode_pm_id(pi->dst_id);
	pr_info("Opening %d/%ld\n", type, id);

	page_server_close();

	if (open_page_xfer(&cxfer.loc_xfer, type, id))
		return -1;

	cxfer.dst_id = pi->dst_id;
	return 0;
}

static int prep_loc_xfer(struct page_server_iov *pi)
{
	if (cxfer.dst_id != pi->dst_id) {
		pr_warn("Deprecated IO w/o open\n");
		return page_server_open(pi);
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

	iov.iov_base = decode_pointer(pi->vaddr);
	iov.iov_len = pi->nr_pages * PAGE_SIZE;

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

	iov.iov_base = decode_pointer(pi->vaddr);
	iov.iov_len = pi->nr_pages * PAGE_SIZE;

	if (lxfer->write_hole(lxfer, &iov))
		return -1;

	return 0;
}

static int page_server_serve(int sk)
{
	int ret = -1;
	bool flushed = false;

	if (pipe(cxfer.p)) {
		pr_perror("Can't make pipe for xfer");
		close(sk);
		return -1;
	}

	cxfer.pipe_size = fcntl(cxfer.p[0], F_GETPIPE_SZ, 0);
	pr_debug("Created xfer pipe size %u\n", cxfer.pipe_size);

	while (1) {
		struct page_server_iov pi;

		ret = read(sk, &pi, sizeof(pi));
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
			ret = page_server_open(&pi);
			break;
		case PS_IOV_ADD:
			ret = page_server_add(sk, &pi);
			break;
		case PS_IOV_HOLE:
			ret = page_server_hole(sk, &pi);
			break;
		case PS_IOV_FLUSH:
		{
			int32_t status = 0;

			/*
			 * An answer must be sent back to inform another side,
			 * that all data were received
			 */
			if (write(sk, &status, sizeof(status)) != sizeof(status)) {
				pr_perror("Can't send the final package");
				ret = -1;
			}

			flushed = true;
			ret = 0;
			break;
		}
		default:
			pr_err("Unknown command %u\n", pi.cmd);
			ret = -1;
			break;
		}

		if (ret)
			break;
	}

	if (!flushed) {
		pr_err("The data were not flushed");
		ret = -1;
	}

	page_server_close();
	pr_info("Session over\n");

	close(sk);
	return ret;
}

static int get_sockaddr_in(struct sockaddr_in *addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;

	if (!opts.addr)
		addr->sin_addr.s_addr = INADDR_ANY;
	else if (!inet_aton(opts.addr, &addr->sin_addr)) {
		pr_perror("Bad page server address");
		return -1;
	}

	addr->sin_port = opts.ps_port;
	return 0;
}

int cr_page_server(bool daemon_mode)
{
	int sk, ask = -1;
	struct sockaddr_in saddr, caddr;
	socklen_t clen = sizeof(caddr);

	up_page_ids_base();

	pr_info("Starting page server on port %u\n", (int)ntohs(opts.ps_port));

	sk = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0) {
		pr_perror("Can't init page server");
		return -1;
	}

	if (get_sockaddr_in(&saddr))
		goto out;

	if (bind(sk, (struct sockaddr *)&saddr, sizeof(saddr))) {
		pr_perror("Can't bind page server");
		goto out;
	}

	if (listen(sk, 1)) {
		pr_perror("Can't listen on page server socket");
		goto out;
	}

	if (daemon_mode)
		if(daemon(0, 0) == -1){
			pr_perror("Can't run in the background");
			return -errno;
		}

	ask = accept(sk, (struct sockaddr *)&caddr, &clen);
	if (ask < 0)
		pr_perror("Can't accept connection to server");

out:
	close(sk);

	if (ask < 0)
		return -1;

	pr_info("Accepted connection from %s:%u\n",
			inet_ntoa(caddr.sin_addr),
			(int)ntohs(caddr.sin_port));

	return page_server_serve(ask);
}

static int page_server_sk = -1;

int connect_to_page_server(void)
{
	struct sockaddr_in saddr;

	if (!opts.use_page_server)
		return 0;

	pr_info("Connecting to server %s:%u\n",
			opts.addr, (int)ntohs(opts.ps_port));

	page_server_sk = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (page_server_sk < 0) {
		pr_perror("Can't create socket");
		return -1;
	}

	if (get_sockaddr_in(&saddr))
		return -1;

	if (connect(page_server_sk, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		pr_perror("Can't connect to server");
		return -1;
	}

	return 0;
}

int disconnect_from_page_server(void)
{
	struct page_server_iov pi = { .cmd = PS_IOV_FLUSH };
	int32_t status = -1;
	int ret = -1;

	if (!opts.use_page_server)
		return 0;

	if (page_server_sk == -1)
		return 0;

	pr_info("Disconnect from the page server %s:%u\n",
			opts.addr, (int)ntohs(opts.ps_port));

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

static int write_pagemap_to_server(struct page_xfer *xfer,
		struct iovec *iov)
{
	struct page_server_iov pi;

	pi.cmd = PS_IOV_ADD;
	pi.dst_id = xfer->dst_id;
	pi.vaddr = encode_pointer(iov->iov_base);
	pi.nr_pages = iov->iov_len / PAGE_SIZE;

	if (write(xfer->fd, &pi, sizeof(pi)) != sizeof(pi)) {
		pr_perror("Can't write pagemap to server");
		return -1;
	}

	return 0;
}

static int write_pages_to_server(struct page_xfer *xfer,
		int p, unsigned long len)
{
	pr_debug("Splicing %lu bytes / %lu pages into socket\n", len, len / PAGE_SIZE);

	if (splice(p, NULL, xfer->fd, NULL, len, SPLICE_F_MOVE) != len) {
		pr_perror("Can't write pages to socket");
		return -1;
	}

	return 0;
}

static int write_hole_to_server(struct page_xfer *xfer, struct iovec *iov)
{
	struct page_server_iov pi;

	pi.cmd = PS_IOV_HOLE;
	pi.dst_id = xfer->dst_id;
	pi.vaddr = encode_pointer(iov->iov_base);
	pi.nr_pages = iov->iov_len / PAGE_SIZE;

	if (write(xfer->fd, &pi, sizeof(pi)) != sizeof(pi)) {
		pr_perror("Can't write pagehole to server");
		return -1;
	}

	return 0;
}

static void close_server_xfer(struct page_xfer *xfer)
{
	xfer->fd = -1;
}

static int open_page_server_xfer(struct page_xfer *xfer, int fd_type, long id)
{
	struct page_server_iov pi;

	xfer->fd = page_server_sk;
	xfer->write_pagemap = write_pagemap_to_server;
	xfer->write_pages = write_pages_to_server;
	xfer->write_hole = write_hole_to_server;
	xfer->close = close_server_xfer;
	xfer->dst_id = encode_pm_id(fd_type, id);

	pi.cmd = PS_IOV_OPEN;
	pi.dst_id = xfer->dst_id;
	pi.vaddr = 0;
	pi.nr_pages = 0;

	if (write(xfer->fd, &pi, sizeof(pi)) != sizeof(pi)) {
		pr_perror("Can't write to page server");
		return -1;
	}

	return 0;
}

static int write_pagemap_loc(struct page_xfer *xfer,
		struct iovec *iov)
{
	PagemapEntry pe = PAGEMAP_ENTRY__INIT;

	pe.vaddr = encode_pointer(iov->iov_base);
	pe.nr_pages = iov->iov_len / PAGE_SIZE;

	return pb_write_one(xfer->fd, &pe, PB_PAGEMAP);
}

static int write_pages_loc(struct page_xfer *xfer,
		int p, unsigned long len)
{
	if (splice(p, NULL, xfer->fd_pg, NULL, len, SPLICE_F_MOVE) != len)
		return -1;

	return 0;
}

static int write_pagehole_loc(struct page_xfer *xfer, struct iovec *iov)
{
	PagemapEntry pe = PAGEMAP_ENTRY__INIT;

	pe.vaddr = encode_pointer(iov->iov_base);
	pe.nr_pages = iov->iov_len / PAGE_SIZE;
	pe.has_in_parent = true;
	pe.in_parent = true;

	if (pb_write_one(xfer->fd, &pe, PB_PAGEMAP) < 0)
		return -1;

	return 0;
}

static void close_page_xfer(struct page_xfer *xfer)
{
	close(xfer->fd_pg);
	close(xfer->fd);
}

int page_xfer_dump_pages(struct page_xfer *xfer, struct page_pipe *pp,
		unsigned long off)
{
	struct page_pipe_buf *ppb;
	struct iovec *hole = NULL;

	pr_debug("Transfering pages:\n");

	if (pp->free_hole)
		hole = &pp->holes[0];

	list_for_each_entry(ppb, &pp->bufs, l) {
		int i;

		pr_debug("\tbuf %d/%d\n", ppb->pages_in, ppb->nr_segs);

		for (i = 0; i < ppb->nr_segs; i++) {
			struct iovec *iov = &ppb->iov[i];

			while (hole && (hole->iov_base < iov->iov_base)) {
				pr_debug("\th %p [%u]\n", hole->iov_base,
						(unsigned int)(hole->iov_len / PAGE_SIZE));
				if (xfer->write_hole(xfer, hole))
					return -1;

				hole++;
				if (hole >= &pp->holes[pp->free_hole])
					hole = NULL;
			}

			BUG_ON(iov->iov_base < (void *)off);
			iov->iov_base -= off;
			pr_debug("\tp %p [%u]\n", iov->iov_base,
					(unsigned int)(iov->iov_len / PAGE_SIZE));

			if (xfer->write_pagemap(xfer, iov))
				return -1;
			if (xfer->write_pages(xfer, ppb->p[0], iov->iov_len))
				return -1;
		}
	}

	while (hole) {
		pr_debug("\th* %p [%u]\n", hole->iov_base,
				(unsigned int)(hole->iov_len / PAGE_SIZE));
		if (xfer->write_hole(xfer, hole))
			return -1;

		hole++;
		if (hole >= &pp->holes[pp->free_hole])
			hole = NULL;
	}

	return 0;
}

static int open_page_local_xfer(struct page_xfer *xfer, int fd_type, long id)
{
	xfer->fd = open_image(fd_type, O_DUMP, id);
	if (xfer->fd < 0)
		return -1;

	xfer->fd_pg = open_pages_image(O_DUMP, xfer->fd);
	if (xfer->fd_pg < 0) {
		close(xfer->fd);
		return -1;
	}

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
