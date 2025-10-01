#ifndef __CR_PAGE_PIPE_H__
#define __CR_PAGE_PIPE_H__

#include <sys/uio.h>
#include "common/list.h"

#define PAGE_ALLOC_COSTLY_ORDER 3 /* from the kernel source code */
struct kernel_pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private;
};

/*
 * The kernel allocates the linear chunk of memory for pipe buffers.
 * Allocation of chunks with size more than PAGE_ALLOC_COSTLY_ORDER
 * fails very often, so we need to restrict the pipe capacity to not
 * allocate big chunks.
 */
#define PIPE_MAX_SIZE ((1 << PAGE_ALLOC_COSTLY_ORDER) * PAGE_SIZE / sizeof(struct kernel_pipe_buffer))

/* The number of pipes for one chunk */
#define NR_PIPES_PER_CHUNK 8

/*
 * page_pipe is a descriptor of task's virtual memory
 * with pipes, containing pages.
 *
 * A page-pipe may contain holes -- these are pagemap
 * entries without pages. Holes are stored in separate
 * array to optimize paged iovs feed into vmsplice --
 * they will be sent there in one go.
 *
 * A hole is a pagemap entry that doesn't have pages
 * in it, since they are present in previous (parent)
 * snapshot.
 *
 *
 * This page-pipe vs holes vs task vmem vs image layout
 * is described below.
 *
 * Task memory: (+ present, - not present pages)
 *    0  0  0    0     1      1   1
 *    0  3  6    B     1      8   C
 *    ---+++-----++++++-------++++----
 *
 * Page-pipe iovs:
 *
 *    bufs = 03:3,0B:6,18:4
 *    holes = <empty>
 *
 * The pagemap.img would purely contain page-pipe bufs.
 *
 * Pages image will contain pages at
 *
 *    03,04,05,0B,0C,0D,0E,0F,10,18,19,1A,1B
 *
 * stored one by one.
 *
 * Not let's imagine task touches some pages and its mem
 * looks like: (+ present, = old present, - non present)
 *
 *    0  0  0    0     11    11   1
 *    0  3  6    B     12    78   C
 *    ---==+-----====+++-----++===----
 *
 * (not new pages at 11 and 17 vaddrs)
 *
 * The new --snapshot'ed page-pipe would look like
 *
 *    bufs = 05:1,0F:3,17:2
 *    holes = 03:2,0B:4,19:3
 *
 * So the pagemap.img would look like
 *
 *    03:2:P,05:1,0B:4:P,0F:3,17:2,19:3:P
 *
 * (the page_xfer_dump_pages generates one)
 *
 * where P means "in parent", i.e. respective pages should
 * be looked up in the parent pagemap (not pages.img, but
 * the pagemap, and then the offset in previous pages.img
 * should be calculated, see the read_pagemap_page routine).
 *
 * New pages.img file would contain only pages for
 *
 *    05,0F,10,11,17,18
 */

struct page_pipe_buf {
	int p[2];		/* pipe with pages */
	unsigned int pipe_size; /* how many pages can be fit into pipe */
	unsigned int nr_segs;	/* how many iov-s are busy */
	unsigned long pipe_off;	/* where this buf is started in a pipe */
	unsigned long pages_in;	/* how many pages are there */
#define PPB_LAZY (1 << 0)
	unsigned int flags;
	struct iovec *iov;  /* vaddr:len map */
	struct list_head l; /* links into page_pipe->bufs */
};

/*
 * Page pipe buffers with different flags cannot share the same pipe.
 * We track the last ppb that was used for each type separately in the
 * prev[] array in the struct page_pipe (below).
 * Currently we have 2 types: the buffers that are always stored in
 * the images and the buffers that are lazily migrated
 */
#define PP_PIPE_TYPES 2

#define PP_HOLE_PARENT (1 << 0)

struct page_pipe {
	unsigned int nr_pipes;			   /* how many page_pipe_bufs in there */
	struct list_head bufs;			   /* list of bufs */
	struct list_head free_bufs;		   /* list of bufs */
	struct page_pipe_buf *prev[PP_PIPE_TYPES]; /* last ppb of each type for pipe sharing */
	unsigned int nr_iovs;			   /* number of iovs */
	unsigned int free_iov;			   /* first free iov */

	struct iovec *iovs; /* iovs. They are provided into create_page_pipe
							   and all bufs have their iov-s in there */

	unsigned int nr_holes;	/* number of holes allocated */
	unsigned int free_hole; /* number of holes in use */
	struct iovec *holes;	/* holes */
	unsigned int *hole_flags;
	unsigned int flags; /* PP_FOO flags below */
};

#define PP_CHUNK_MODE 0x1 /* Restrict the maximum buffer size of pipes and dump memory for a few iterations */
#define PP_OWN_IOVS   0x4 /* create_page_pipe allocated IOVs memory */

struct page_pipe *create_page_pipe(unsigned int nr_segs, struct iovec *iovs, unsigned flags);
extern void destroy_page_pipe(struct page_pipe *p);
extern int page_pipe_add_page(struct page_pipe *p, unsigned long addr, unsigned int flags);
extern int page_pipe_add_hole(struct page_pipe *pp, unsigned long addr, unsigned int flags);

extern void debug_show_page_pipe(struct page_pipe *pp);
void page_pipe_reinit(struct page_pipe *pp);

extern void page_pipe_destroy_ppb(struct page_pipe_buf *ppb);

struct pipe_read_dest {
	int p[2];
	int sink_fd;
};

extern int pipe_read_dest_init(struct pipe_read_dest *prd);
extern int page_pipe_read(struct page_pipe *pp, struct pipe_read_dest *prd, unsigned long addr, unsigned long *nr_pages,
			  unsigned int ppb_flags);

#endif /* __CR_PAGE_PIPE_H__ */
