#ifndef __CR_PAGE_XFER__H__
#define __CR_PAGE_XFER__H__
struct page_xfer {
	int (*write_pagemap)(struct page_xfer *self, struct iovec *iov, int pipe);
	void (*close)(struct page_xfer *self);
	int fd;
	union {
		int fd_pg;
	};
};

int open_page_xfer(struct page_xfer *xfer, int fd_type, long id);
#endif
