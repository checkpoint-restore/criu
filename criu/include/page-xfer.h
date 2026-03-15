#ifndef __CR_PAGE_XFER__H__
#define __CR_PAGE_XFER__H__
#include "pagemap.h"

struct ps_info {
	int pid;
	unsigned short port;
};

extern int cr_page_server(bool daemon_mode, bool lazy_dump, int cfd);

/* User buffer for read-mode pre-dump*/
#define PIPE_MAX_BUFFER_SIZE (PIPE_MAX_SIZE << PAGE_SHIFT)

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

	/*
	 * Local non-streaming dump only: the pages image fd was switched to
	 * O_DIRECT (--image-io-mode=direct). write_pages_loc() splices with
	 * O_DIRECT set and clears this if the filesystem rejects direct I/O.
	 */
	bool pi_use_direct;
	/* Bytes already emitted to the pages image, including alignment padding. */
	uint64_t pages_image_offset;

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

	/*
	 * Pending pagemap entry for compressed writes.
	 * write_pagemap saves the entry here because the
	 * compressed_size array is not known until write_pages
	 * compresses all pages. Once done, write_pages writes
	 * the complete pagemap entry.
	 *
	 * In region mode (region_pages > 0) the compressed_size[]
	 * array holds one element per region (length n_compressed
	 * == ceil(nr_pages / region_pages)).
	 */
	struct {
		unsigned long vaddr;
		unsigned long nr_pages;
		u32 flags;
		uint32_t *compressed_size;
		uint64_t total_compressed_size;
		/* Number of compressed blocks emitted so far. */
		size_t n_compressed;
		/* Total expected blocks (nr_pages for per-page, regions for region). */
		size_t total_blocks;
		/* 0 = per-page mode; >0 = region mode region size in pages. */
		unsigned int region_pages;
		/* Whether this entry has emitted its first non-zero payload. */
		bool payload_started;
	} pending_pe;
};

extern int open_page_xfer(struct page_xfer *xfer, int fd_type, unsigned long id);
struct page_pipe;
extern int page_xfer_dump_pages(struct page_xfer *, struct page_pipe *);
extern int page_xfer_predump_pages(int pid, struct page_xfer *, struct page_pipe *);
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
extern int request_remote_pages(unsigned long img_id, unsigned long addr, unsigned long nr_pages);

typedef int (*ps_async_read_complete)(unsigned long img_id, unsigned long vaddr, unsigned long nr_pages, void *);
extern int page_server_start_read(void *buf, unsigned long nr_pages, ps_async_read_complete complete, void *priv, unsigned flags);

#endif /* __CR_PAGE_XFER__H__ */
