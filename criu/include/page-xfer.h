#ifndef __CR_PAGE_XFER__H__
#define __CR_PAGE_XFER__H__
#include "pagemap.h"

struct ps_info {
	int pid;
	unsigned short port;
};

extern int cr_page_server(bool daemon_mode, bool lazy_dump, int cfd);

/*
 * page_xfer -- transfer pages into image file.
 * Two images backends are implemented -- local image file
 * and page-server image file.
 */

struct page_xfer {
	/* transfers one vaddr:len entry */
	int (*write_pagemap)(struct page_xfer *self, struct iovec *iov, u32 flags);
	/* transfers pages related to previous pagemap */
	int (*write_pages)(struct page_xfer *self, int pipe, unsigned long len);
	void (*close)(struct page_xfer *self);

	/*
	 * In case we need to dump pagemaps not as-is, but
	 * relative to some address. Used, e.g. by shmem.
	 */
	unsigned long offset;
	bool transfer_lazy;

	/* private data for every page-xfer engine */
	union {
		struct /* local */ {
			struct cr_img *pmi; /* pagemaps */
			struct cr_img *pi;  /* pages */
		};

		struct /* page-server */ {
			int sk;
			u64 dst_id;
		};
	};

	struct page_read *parent;
};

extern int open_page_xfer(struct page_xfer *xfer, int fd_type, unsigned long id);
struct page_pipe;
extern int page_xfer_dump_pages(struct page_xfer *, struct page_pipe *);
extern int connect_to_page_server_to_send(void);
extern int connect_to_page_server_to_recv(int epfd);
extern int disconnect_from_page_server(void);

extern int check_parent_page_xfer(int fd_type, unsigned long id);

/*
 * The post-copy migration makes it necessary to receive pages from
 * remote dump. The protocol we use for that is quite simple:
 * - lazy-pages sends request containing PS_IOV_GET(nr_pages, vaddr, pid)
 * - dump-side page server responds with PS_IOV_ADD(nr_pages, vaddr,
     pid) or PS_IOV_ADD(0, 0, 0) if it failed to locate the required
     pages
 * - dump-side page server sends the raw page data
 */

/* async request/receive of remote pages */
extern int request_remote_pages(unsigned long img_id, unsigned long addr, int nr_pages);

typedef int (*ps_async_read_complete)(unsigned long img_id, unsigned long vaddr, int nr_pages, void *);
extern int page_server_start_read(void *buf, int nr_pages,
		ps_async_read_complete complete, void *priv, unsigned flags);

#endif /* __CR_PAGE_XFER__H__ */
