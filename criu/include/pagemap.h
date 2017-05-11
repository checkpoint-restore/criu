#ifndef __CR_PAGE_READ_H__
#define __CR_PAGE_READ_H__

#include "common/list.h"
#include "images/pagemap.pb-c.h"
#include "page.h"

/*
 * page_read -- engine, that reads pages from image file(s)
 *
 * Several page-read's can be arranged in a chain to read
 * pages from a series of snapshot.
 *
 * A task's address space vs pagemaps+page image pairs can
 * look like this (taken from comment in page-pipe.h):
 *
 * task:
 *
 *       0  0  0    0      1    1    1
 *       0  3  6    B      2    7    C
 *       ---+++-----+++++++-----+++++----
 * pm1:  ---+++-----++++++-------++++----
 * pm2:  ---==+-----====+++-----++===----
 *
 * Here + is present page, - is non prsent, = is present,
 * but is not modified from last snapshot.
 *
 * Thus pagemap.img and pages.img entries are
 *
 * pm1:  03:3,0B:6,18:4
 * pm2:  03:2:P,05:1,0B:4:P,0F:3,17:2,19:3:P
 *
 * where P means "page is in parent pagemap".
 *
 * pg1:  03,04,05,0B,0C,0D,0E,0F,10,18,19,1A,1B
 * pg2:  05,0F,10,11,17,18
 *
 * When trying to restore from these 4 files we'd have
 * to carefully scan pagemap.img's one by one and read or
 * skip pages from pages.img where appropriate.
 *
 * All this is implemented in read_pagemap_page.
 */

struct page_read {
	/* reads page from current pagemap */
	int (*read_pages)(struct page_read *, unsigned long vaddr, int nr,
			  void *, unsigned flags);
	/* Advance page_read to the next entry (including zero pagemaps) */
	int (*advance)(struct page_read *pr);
	void (*close)(struct page_read *);
	int (*sync)(struct page_read *pr);
	int (*seek_pagemap)(struct page_read *pr, unsigned long vaddr);

	/* Private data of reader */
	struct cr_img *pmi;
	struct cr_img *pi;
	u32 pages_img_id;

	PagemapEntry *pe;		/* current pagemap we are on */
	struct page_read *parent;	/* parent pagemap (if ->in_parent
					   pagemap is met in image, then
					   go to this guy for page, see
					   read_pagemap_page */
	unsigned long cvaddr;		/* vaddr we are on */
	off_t pi_off;			/* current offset in pages file */

	struct iovec bunch;		/* record consequent neighbour
					   iovecs to punch together */
	unsigned id; /* for logging */

	PagemapEntry **pmes;
	int nr_pmes;
	int curr_pme;

	struct list_head	async;
};

/* flags for ->read_pages */
#define PR_ASYNC	0x1 /* may exit w/o data in the buffer */

/* flags for open_page_read */
#define PR_SHMEM	0x1
#define PR_TASK		0x2

#define PR_TYPE_MASK	0x3
#define PR_MOD		0x4	/* Will need to modify */

/*
 * -1 -- error
 *  0 -- no images
 *  1 -- opened
 */
extern int open_page_read(int pid, struct page_read *, int pr_flags);
extern int open_page_read_at(int dfd, int pid, struct page_read *pr,
		int pr_flags);

int pagemap_enqueue_iovec(struct page_read *pr, void *buf,
			      unsigned long len, struct list_head *to);

extern int dedup_one_iovec(struct page_read *pr, unsigned long base,
			   unsigned long len);

static inline unsigned long pagemap_len(PagemapEntry *pe)
{
	return pe->nr_pages * PAGE_SIZE;
}
#endif /* __CR_PAGE_READ_H__ */
