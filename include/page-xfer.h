#ifndef __CR_PAGE_XFER__H__
#define __CR_PAGE_XFER__H__
#include "page-read.h"

extern int cr_page_server(bool daemon_mode);

/*
 * page_xfer -- transfer pages into image file.
 * Two images backends are implemented -- local image file
 * and page-server image file.
 */

struct page_xfer {
	/* transfers one vaddr:len entry */
	int (*write_pagemap)(struct page_xfer *self, struct iovec *iov);
	/* transfers pages related to previous pagemap */
	int (*write_pages)(struct page_xfer *self, int pipe, unsigned long len);
	/* transfers one hole -- vaddr:len entry w/o pages */
	int (*write_hole)(struct page_xfer *self, struct iovec *iov);
	void (*close)(struct page_xfer *self);

	/* private data for every page-xfer engine */
	int fd;
	union {
		int fd_pg;
		u64 dst_id;
	};
	struct page_read *parent;
};

extern int open_page_xfer(struct page_xfer *xfer, int fd_type, long id);
struct page_pipe;
extern int page_xfer_dump_pages(struct page_xfer *, struct page_pipe *,
				unsigned long off);
extern int connect_to_page_server(void);
extern int disconnect_from_page_server(void);

#endif /* __CR_PAGE_XFER__H__ */
