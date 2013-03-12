#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "crtools.h"
#include "page-xfer.h"

#include "protobuf.h"
#include "protobuf/pagemap.pb-c.h"

struct page_server_iov {
	u32	cmd;
	u32	nr_pages;
	u64	vaddr;
	u64	dst_id;
};

#define PS_IOV_ADD	1

#define PS_TYPE_BITS	4
#define PS_TYPE_MASK	((1 << PS_TYPE_BITS) - 1)

static inline u64 encode_pm_id(int type, int id)
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

static int page_server_add(int sk, struct page_server_iov *pi)
{
	size_t len;
	struct page_xfer *lxfer = &cxfer.loc_xfer;
	PagemapEntry pe = PAGEMAP_ENTRY__INIT;

	pr_debug("Adding %lx/%u\n", pi->vaddr, pi->nr_pages);

	if (cxfer.dst_id != pi->dst_id) {
		if (cxfer.dst_id != ~0)
			cxfer.loc_xfer.close(&cxfer.loc_xfer);

		if (open_page_xfer(&cxfer.loc_xfer,
					decode_pm_type(pi->dst_id),
					decode_pm_id(pi->dst_id)))
			return -1;

		cxfer.dst_id = pi->dst_id;
	}

	pe.vaddr = pi->vaddr;
	pe.nr_pages = pi->nr_pages;

	if (pb_write_one(lxfer->fd, &pe, PB_PAGEMAP) < 0)
		return -1;

	len = pe.nr_pages * PAGE_SIZE;
	while (len > 0) {
		ssize_t ret, chunk;

		chunk = len;
		if (chunk > cxfer.pipe_size)
			chunk = cxfer.pipe_size;

		chunk = splice(sk, NULL, cxfer.p[1], NULL, chunk, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
		if (chunk < 0) {
			pr_perror("Can't read from socket");
			return -1;
		}

		ret = splice(cxfer.p[0], NULL, lxfer->fd_pg, NULL, chunk, SPLICE_F_MOVE);
		if (ret < 0) {
			pr_perror("Can't put pages into file");
			return -1;
		}
		if (ret != chunk) {
			pr_perror("Partial image write %ld/%ld\n", ret, chunk);
			return -1;
		}

		len -= chunk;
	}

	return 0;
}

static int page_server_serve(int sk)
{
	if (pipe(cxfer.p)) {
		pr_perror("Can't make pipe for xfer");
		return -1;
	}

	cxfer.pipe_size = fcntl(cxfer.p[0], F_GETPIPE_SZ, 0);
	pr_debug("Created xfer pipe size %u\n", cxfer.pipe_size);

	while (1) {
		int ret;
		struct page_server_iov pi;

		ret = read(sk, &pi, sizeof(pi));
		if (!ret)
			break;

		if (ret != sizeof(pi)) {
			pr_perror("Can't read pagemap from socket");
			return -1;
		}

		switch (pi.cmd) {
		case PS_IOV_ADD:
			ret = page_server_add(sk, &pi);
			break;
		default:
			pr_err("Unknown command %u\n", pi.cmd);
			ret = -1;
			break;
		}

		if (ret)
			return -1;
	}

	pr_info("Session over\n");
	return 0;
}

int cr_page_server(void)
{
	int sk, ask;
	struct sockaddr_in caddr;
	socklen_t clen = sizeof(caddr);

	pr_info("Starting page server on port %u\n",
			(int)ntohs(opts.ps_addr.sin_port));

	sk = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0) {
		pr_perror("Can't init page server\n");
		return -1;
	}

	opts.ps_addr.sin_family = AF_INET;
	if (bind(sk, (struct sockaddr *)&opts.ps_addr, sizeof(opts.ps_addr))) {
		pr_perror("Can't bind page server\n");
		return -1;
	}

	if (listen(sk, 1)) {
		pr_perror("Can't listen on page server socket");
		return -1;
	}

	ask = accept(sk, (struct sockaddr *)&caddr, &clen);
	if (ask < 0) {
		pr_perror("Can't accept connection to server");
		return -1;
	}

	close(sk);

	pr_info("Accepted connection from %s:%u\n",
			inet_ntoa(caddr.sin_addr),
			(int)ntohs(caddr.sin_port));

	return page_server_serve(ask);
}

static int page_server_sk = -1;

int connect_to_page_server(void)
{
	if (!opts.use_page_server)
		return 0;

	pr_info("Connecting to server %s:%u\n",
			inet_ntoa(opts.ps_addr.sin_addr),
			(int)ntohs(opts.ps_addr.sin_port));

	page_server_sk = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (page_server_sk < 0) {
		pr_perror("Can't create socket\n");
		return -1;
	}

	opts.ps_addr.sin_family = AF_INET;
	if (connect(page_server_sk, (struct sockaddr *)&opts.ps_addr,
				sizeof(opts.ps_addr)) < 0) {
		pr_perror("Can't connect to server\n");
		return -1;
	}

	return 0;
}

static int write_pagemap_to_server(struct page_xfer *xfer,
		struct iovec *iov, int p)
{
	struct page_server_iov pi;

	pi.cmd = PS_IOV_ADD;
	pi.dst_id = xfer->dst_id;
	pi.vaddr = encode_pointer(iov->iov_base);
	pi.nr_pages = iov->iov_len / PAGE_SIZE;

	if (write(xfer->fd, &pi, sizeof(pi)) != sizeof(pi)) {
		pr_perror("Can't write pagemap to server\n");
		return -1;
	}

	pr_debug("Splicing %lu bytes / %u pages into socket\n", iov->iov_len, pi.nr_pages);
	if (splice(p, NULL, xfer->fd, NULL, iov->iov_len,
				SPLICE_F_MOVE) != iov->iov_len) {
		pr_perror("Can't write pages to socket");
		return -1;
	}

	return 0;
}

static void close_server_xfer(struct page_xfer *xfer)
{
	xfer->fd = -1;
}

int open_page_server_xfer(struct page_xfer *xfer, int fd_type, long id)
{
	xfer->fd = page_server_sk;
	xfer->write_pagemap = write_pagemap_to_server;
	xfer->close = close_server_xfer;
	xfer->dst_id = encode_pm_id(fd_type, id);

	return 0;
}

static int write_pagemap_loc(struct page_xfer *xfer,
		struct iovec *iov, int p)
{
	PagemapEntry pe = PAGEMAP_ENTRY__INIT;

	pe.vaddr = encode_pointer(iov->iov_base);
	pe.nr_pages = iov->iov_len / PAGE_SIZE;

	if (pb_write_one(xfer->fd, &pe, PB_PAGEMAP) < 0)
		return -1;

	if (splice(p, NULL, xfer->fd_pg, NULL, iov->iov_len,
				SPLICE_F_MOVE) != iov->iov_len)
		return -1;

	return 0;
}

static void close_page_xfer(struct page_xfer *xfer)
{
	close(xfer->fd_pg);
	close(xfer->fd);
}

int open_page_xfer(struct page_xfer *xfer, int fd_type, long id)
{
	if (opts.use_page_server)
		return open_page_server_xfer(xfer, fd_type, id);

	xfer->fd = open_image(fd_type, O_DUMP, id);
	if (xfer->fd < 0)
		return -1;

	xfer->fd_pg = open_pages_image(O_DUMP, xfer->fd);
	if (xfer->fd_pg < 0) {
		close(xfer->fd);
		return -1;
	}

	xfer->write_pagemap = write_pagemap_loc;
	xfer->close = close_page_xfer;
	return 0;
}
