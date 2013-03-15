#ifndef __CR_PAGE_XFER__H__
#define __CR_PAGE_XFER__H__
int cr_page_server(void);

struct page_xfer {
	int (*write_pagemap)(struct page_xfer *self, struct iovec *iov, int pipe);
	void (*close)(struct page_xfer *self);
	int fd;
	union {
		int fd_pg;
		u64 dst_id;
	};
};

int open_page_xfer(struct page_xfer *xfer, int fd_type, long id);
int open_page_server_xfer(struct page_xfer *, int fd_type, long id);
struct page_pipe;
int page_xfer_dump_pages(struct page_xfer *, struct page_pipe *,
		unsigned long off);
int connect_to_page_server(void);
#endif
