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
		pr_err("Can't read mapping page %d\n", ret);
		return -1;
	}

	return 1;
}

static inline void pagemap2iovec(PagemapEntry *pe, struct iovec *iov)
{
	iov->iov_base = decode_pointer(pe->vaddr);
	iov->iov_len = pe->nr_pages * PAGE_SIZE;
}

static int get_pagemap(struct page_read *pr, struct iovec *iov)
{
	int ret;
	PagemapEntry *pe;

	ret = pb_read_one_eof(pr->fd, &pe, PB_PAGEMAP);
	if (ret <= 0)
		return ret;

	pagemap2iovec(pe, iov);

	pr->pe = pe;
	pr->cvaddr = (unsigned long)iov->iov_base;

	if (pe->in_parent && !pr->parent) {
		pr_err("No parent for snapshot pagemap\n");
		return -1;
	}

	return 1;
}

static void put_pagemap(struct page_read *pr)
{
	pagemap_entry__free_unpacked(pr->pe, NULL);
}

static int read_pagemap_page(struct page_read *pr, unsigned long vaddr, void *buf);

static void skip_pagemap_pages(struct page_read *pr, unsigned long len)
{
	if (!len)
		return;

	pr_debug("\tpr%u Skip %lx bytes from page-dump\n", pr->id, len);
	if (!pr->pe->in_parent)
		lseek(pr->fd_pg, len, SEEK_CUR);
	pr->cvaddr += len;
}

static int read_pagemap_page_from_parent(struct page_read *pr, unsigned long vaddr, void *buf)
{
	int ret;
	struct iovec iov;

	if (pr->pe)
		pagemap2iovec(pr->pe, &iov);
	else
		goto new_pagemap;

	while (1) {
		unsigned long iov_end;

		BUG_ON(vaddr < pr->cvaddr);
		iov_end = (unsigned long)iov.iov_base + iov.iov_len;

		if (iov_end <= vaddr) {
			skip_pagemap_pages(pr, iov_end - pr->cvaddr);
			put_pagemap(pr);
new_pagemap:
			ret = get_pagemap(pr, &iov);
			if (ret <= 0)
				return -1;

			continue;
		}

		skip_pagemap_pages(pr, vaddr - pr->cvaddr);
		return read_pagemap_page(pr, vaddr, buf);
	}
}

static int read_pagemap_page(struct page_read *pr, unsigned long vaddr, void *buf)
{
	int ret;

	if (pr->pe->in_parent) {
		pr_debug("\tpr%u Read page %lx from parent\n", pr->id, vaddr);
		ret = read_pagemap_page_from_parent(pr->parent, vaddr, buf);
	} else {
		pr_debug("\tpr%u Read page %lx from self %lx/%"PRIx64"\n", pr->id,
				vaddr, pr->cvaddr, lseek(pr->fd_pg, 0, SEEK_CUR));
		ret = read(pr->fd_pg, buf, PAGE_SIZE);
		if (ret != PAGE_SIZE) {
			pr_err("Can't read mapping page %d\n", ret);
			return -1;
		}
	}

	pr->cvaddr += PAGE_SIZE;

	return 1;
}

static void close_page_read(struct page_read *pr)
{
	if (pr->parent) {
		close_page_read(pr->parent);
		xfree(pr->parent);
	}

	close(pr->fd_pg);
	close(pr->fd);
}

static int open_page_read_at(int dfd, int pid, struct page_read *pr);

static int try_open_parent(int dfd, int pid, struct page_read *pr)
{
	int pfd;
	struct page_read *parent = NULL;

	pfd = openat(dfd, CR_PARENT_LINK, O_RDONLY);
	if (pfd < 0 && errno == ENOENT)
		goto out;

	parent = xmalloc(sizeof(*parent));
	if (!parent)
		goto err_cl;

	if (open_page_read_at(pfd, pid, parent))
		goto err_free;

	close(pfd);
out:
	pr->parent = parent;
	return 0;

err_free:
	xfree(parent);
err_cl:
	close(pfd);
	return -1;
}

static int open_page_read_at(int dfd, int pid, struct page_read *pr)
{
	pr->fd = open_image_at(dfd, CR_FD_PAGEMAP, O_RSTR, (long)pid);
	if (pr->fd < 0) {
		pr->fd_pg = open_image_at(dfd, CR_FD_PAGES_OLD, O_RSTR, pid);
		if (pr->fd_pg < 0)
			return -1;

		pr->parent = NULL;
		pr->get_pagemap = get_page_vaddr;
		pr->put_pagemap = NULL;
		pr->read_page = read_page;
	} else {
		static unsigned ids = 1;

		if (try_open_parent(dfd, pid, pr)) {
			close(pr->fd);
			return -1;
		}

		pr->fd_pg = open_pages_image_at(dfd, O_RSTR, pr->fd);
		if (pr->fd_pg < 0) {
			close_page_read(pr);
			return -1;
		}

		pr->get_pagemap = get_pagemap;
		pr->put_pagemap = put_pagemap;
		pr->read_page = read_pagemap_page;
		pr->id = ids++;

		pr_debug("Opened page read %u (parent %u)\n",
				pr->id, pr->parent ? pr->parent->id : 0);
	}

	pr->close = close_page_read;

	return 0;
}

int open_page_read(int pid, struct page_read *pr)
{
	return open_page_read_at(get_service_fd(IMG_FD_OFF), pid, pr);
}
