#ifndef __CR_PAGE_READ_H__
#define __CR_PAGE_READ_H__
#include "protobuf/pagemap.pb-c.h"

struct page_read {
	int (*get_pagemap)(struct page_read *, struct iovec *iov);
	int (*read_page)(struct page_read *, unsigned long vaddr, void *);
	void (*put_pagemap)(struct page_read *);
	void (*close)(struct page_read *);

	int fd;
	int fd_pg;
};

int open_page_read(int pid, struct page_read *);
#endif
