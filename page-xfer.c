#include <unistd.h>

#include "crtools.h"
#include "page-xfer.h"

#include "protobuf.h"
#include "protobuf/pagemap.pb-c.h"

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
