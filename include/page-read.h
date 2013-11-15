#ifndef __CR_PAGE_READ_H__
#define __CR_PAGE_READ_H__

#include "protobuf/pagemap.pb-c.h"

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
 * to carefull scan pagemap.img's one by one and read or
 * skip pages from pages.img where appropriate.
 *
 * All this is implemented in read_pagemap_page.
 */

struct page_read {
	/*
	 * gets next vaddr:len pair to work on.
	 * Pagemap entries should be returned in sorted order.
	 */
	int (*get_pagemap)(struct page_read *, struct iovec *iov);
	/* reads page from current pagemap */
	int (*read_page)(struct page_read *, unsigned long vaddr, void *);
	/* stop working on current pagemap */
	void (*put_pagemap)(struct page_read *);
	void (*close)(struct page_read *);

	/* Private data of reader */
	int fd;
	int fd_pg;

	PagemapEntry *pe;		/* current pagemap we are on */
	struct page_read *parent;	/* parent pagemap (if ->in_parent
					   pagemap is met in image, then
					   go to this guy for page, see
					   read_pagemap_page */
	unsigned long cvaddr;		/* vaddr we are on */

	unsigned id; /* for logging */
};

extern int open_page_read(int pid, struct page_read *);

#endif /* __CR_PAGE_READ_H__ */
