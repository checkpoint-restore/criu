#ifndef __CR_PAGE_PIPE_H__
#define __CR_PAGE_PIPE_H__
#include <sys/uio.h>
#include "list.h"

struct page_pipe_buf {
	int p[2];
	unsigned int pipe_size;	/* how many pages can be fit into pipe */
	unsigned int pages_in;	/* how many pages are there */
	unsigned int nr_segs;	/* how many iov-s are busy */
	struct iovec *iov;
	struct list_head l;
};

struct page_pipe {
	unsigned int nr_pipes;
	struct list_head bufs;
	unsigned int nr_iovs;
	unsigned int free_iov;
	struct iovec *iovs;

	unsigned int nr_holes;
	unsigned int free_hole;
	struct iovec *holes;
};

struct page_pipe *create_page_pipe(unsigned int nr, struct iovec *);
void destroy_page_pipe(struct page_pipe *p);
int page_pipe_add_page(struct page_pipe *p, unsigned long addr);
int page_pipe_add_hole(struct page_pipe *p, unsigned long addr);

void debug_show_page_pipe(struct page_pipe *pp);
#endif
