#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "crtools.h"
#include "page-read.h"

#include "protobuf.h"
#include "protobuf/pagemap.pb-c.h"

static int get_page_vaddr(struct page_read *pr, struct iovec *iov)
{
	int ret;
	__u64 img_va;

	ret = read_img_eof(pr->fd_pg, &img_va);
	if (ret <= 0)
		return ret;

	iov->iov_base = (void *)decode_pointer(img_va);
	iov->iov_len = PAGE_SIZE;

	return 1;
}

static int read_page(struct page_read *pr, unsigned long vaddr, void *buf)
{
	int ret;

	ret = read(pr->fd_pg, buf, PAGE_SIZE);
	if (ret != PAGE_SIZE) {
		pr_err("Can'r read mapping page %d\n", ret);
		return -1;
	}

	return 1;
}

static int get_pagemap(struct page_read *pr, struct iovec *iov)
{
	int ret;
	PagemapEntry *pe;

	ret = pb_read_one_eof(pr->fd, &pe, PB_PAGEMAP);
	if (ret <= 0)
		return ret;

	iov->iov_base = decode_pointer(pe->vaddr);
	iov->iov_len = pe->nr_pages * PAGE_SIZE;
	pagemap_entry__free_unpacked(pe, NULL);

	return 1;
}

static void put_pagemap(struct page_read *pr)
{
}

static int read_pagemap_page(struct page_read *pr, unsigned long vaddr, void *buf)
{
	int ret;

	ret = read(pr->fd_pg, buf, PAGE_SIZE);
	if (ret != PAGE_SIZE) {
		pr_err("Can'r read mapping page %d\n", ret);
		return -1;
	}

	return 1;
}

static void close_page_read(struct page_read *pr)
{
	close(pr->fd_pg);
	close(pr->fd);
}

static int open_page_read_at(int dfd, int pid, struct page_read *pr)
{
	pr->fd = open_image_at(dfd, CR_FD_PAGEMAP, O_RSTR, (long)pid);
	if (pr->fd < 0) {
		pr->fd_pg = open_image_at(dfd, CR_FD_PAGES_OLD, O_RSTR, pid);
		if (pr->fd_pg < 0)
			return -1;

		pr->get_pagemap = get_page_vaddr;
		pr->put_pagemap = NULL;
		pr->read_page = read_page;
	} else {
		pr->fd_pg = open_pages_image_at(dfd, O_RSTR, pr->fd);
		if (pr->fd_pg < 0) {
			close_page_read(pr);
			return -1;
		}

		pr->get_pagemap = get_pagemap;
		pr->put_pagemap = put_pagemap;
		pr->read_page = read_pagemap_page;
	}

	pr->close = close_page_read;

	return 0;
}

int open_page_read(int pid, struct page_read *pr)
{
	return open_page_read_at(get_service_fd(IMG_FD_OFF), pid, pr);
}
