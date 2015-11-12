#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "image.h"
#include "cr_options.h"
#include "servicefd.h"
#include "page-read.h"

#include "protobuf.h"
#include "protobuf/pagemap.pb-c.h"

#ifndef SEEK_DATA
#define SEEK_DATA	3
#define SEEK_HOLE	4
#endif

static int get_page_vaddr(struct page_read *pr, struct iovec *iov)
{
	int ret;
	u64 img_va;

	ret = read_img_eof(pr->pmi, &img_va);
	if (ret <= 0)
		return ret;

	iov->iov_base = (void *)decode_pointer(img_va);
	iov->iov_len = PAGE_SIZE;

	return 1;
}

static int read_page(struct page_read *pr, unsigned long vaddr, int nr, void *buf)
{
	int ret;

	BUG_ON(nr != 1);

	ret = read(img_raw_fd(pr->pmi), buf, PAGE_SIZE);
	if (ret != PAGE_SIZE) {
		pr_err("Can't read mapping page %d\n", ret);
		return -1;
	}

	return 1;
}

void pagemap2iovec(PagemapEntry *pe, struct iovec *iov)
{
	iov->iov_base = decode_pointer(pe->vaddr);
	iov->iov_len = pe->nr_pages * PAGE_SIZE;
}

void iovec2pagemap(struct iovec *iov, PagemapEntry *pe)
{
	pe->vaddr = encode_pointer(iov->iov_base);
	pe->nr_pages = iov->iov_len / PAGE_SIZE;
}

static int get_pagemap(struct page_read *pr, struct iovec *iov)
{
	int ret;
	PagemapEntry *pe;

	ret = pb_read_one_eof(pr->pmi, &pe, PB_PAGEMAP);
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

static int read_pagemap_page(struct page_read *pr, unsigned long vaddr, int nr, void *buf);

static void skip_pagemap_pages(struct page_read *pr, unsigned long len)
{
	if (!len)
		return;

	pr_debug("\tpr%u Skip %lu bytes from page-dump\n", pr->id, len);
	if (!pr->pe->in_parent)
		lseek(img_raw_fd(pr->pi), len, SEEK_CUR);
	pr->cvaddr += len;
}

int seek_pagemap_page(struct page_read *pr, unsigned long vaddr, bool warn)
{
	int ret;
	struct iovec iov;

	if (pr->pe)
		pagemap2iovec(pr->pe, &iov);
	else
		goto new_pagemap;

	while (1) {
		unsigned long iov_end;

		if (vaddr < pr->cvaddr) {
			if (warn)
				pr_err("Missing %lx in parent pagemap, current iov: base=%lx,len=%zu\n",
					vaddr, (unsigned long)iov.iov_base, iov.iov_len);
			return 0;
		}
		iov_end = (unsigned long)iov.iov_base + iov.iov_len;

		if (iov_end <= vaddr) {
			skip_pagemap_pages(pr, iov_end - pr->cvaddr);
			put_pagemap(pr);
new_pagemap:
			ret = get_pagemap(pr, &iov);
			if (ret <= 0)
				return ret;

			continue;
		}

		skip_pagemap_pages(pr, vaddr - pr->cvaddr);
		return 1;
	}
}

static inline void pagemap_bound_check(PagemapEntry *pe, unsigned long vaddr, int nr)
{
	if (vaddr < pe->vaddr || (vaddr - pe->vaddr) / PAGE_SIZE + nr > pe->nr_pages) {
		pr_err("Page read err %"PRIx64":%u vs %lx:%u\n",
				pe->vaddr, pe->nr_pages, vaddr, nr);
		BUG();
	}
}

static int read_pagemap_page(struct page_read *pr, unsigned long vaddr, int nr, void *buf)
{
	int ret;
	unsigned long len = nr * PAGE_SIZE;

	pr_info("pr%u Read %lx %u pages\n", pr->id, vaddr, nr);
	pagemap_bound_check(pr->pe, vaddr, nr);

	if (pr->pe->in_parent) {
		struct page_read *ppr = pr->parent;

		/*
		 * Parent pagemap at this point entry may be shorter
		 * than the current vaddr:nr needs, so we have to
		 * carefully 'split' the vaddr:nr into pieces and go
		 * to parent page-read with the longest requests it
		 * can handle.
		 */

		do {
			int p_nr;

			pr_debug("\tpr%u Read from parent\n", pr->id);
			ret = seek_pagemap_page(ppr, vaddr, true);
			if (ret <= 0)
				return -1;

			/*
			 * This is how many pages we have in the parent
			 * page_read starting from vaddr. Go ahead and
			 * read as much as we can.
			 */
			p_nr = ppr->pe->nr_pages - (vaddr - ppr->pe->vaddr) / PAGE_SIZE;
			pr_info("\tparent has %u pages in\n", p_nr);
			if (p_nr > nr)
				p_nr = nr;

			ret = read_pagemap_page(ppr, vaddr, p_nr, buf);
			if (ret == -1)
				return ret;

			/*
			 * OK, let's see how much data we have left and go
			 * to parent page-read again for the next pagemap
			 * entry.
			 */
			nr -= p_nr;
			vaddr += p_nr * PAGE_SIZE;
			buf += p_nr * PAGE_SIZE;
		} while (nr);
	} else {
		int fd = img_raw_fd(pr->pi);
		off_t current_vaddr = lseek(fd, 0, SEEK_CUR);

		pr_debug("\tpr%u Read page from self %lx/%"PRIx64"\n", pr->id, pr->cvaddr, current_vaddr);
		ret = read(fd, buf, len);
		if (ret != len) {
			pr_perror("Can't read mapping page %d", ret);
			return -1;
		}

		if (opts.auto_dedup) {
			ret = punch_hole(pr, current_vaddr, len, false);
			if (ret == -1) {
				return -1;
			}
		}
	}

	pr->cvaddr += len;

	return 1;
}

static void close_page_read(struct page_read *pr)
{
	int ret;

	if (pr->bunch.iov_len > 0) {
		ret = punch_hole(pr, 0, 0, true);
		if (ret == -1)
			return;

		pr->bunch.iov_len = 0;
	}

	if (pr->parent) {
		close_page_read(pr->parent);
		xfree(pr->parent);
	}

	close_image(pr->pmi);
	if (pr->pi)
		close_image(pr->pi);
}

static int try_open_parent(int dfd, int pid, struct page_read *pr, int pr_flags)
{
	int pfd, ret;
	struct page_read *parent = NULL;

	pfd = openat(dfd, CR_PARENT_LINK, O_RDONLY);
	if (pfd < 0 && errno == ENOENT)
		goto out;

	parent = xmalloc(sizeof(*parent));
	if (!parent)
		goto err_cl;

	ret = open_page_read_at(pfd, pid, parent, pr_flags);
	if (ret < 0)
		goto err_free;

	if (!ret) {
		xfree(parent);
		parent = NULL;
	}

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

int open_page_read_at(int dfd, int pid, struct page_read *pr, int pr_flags)
{
	int flags, i_typ, i_typ_o;
	static unsigned ids = 1;

	if (opts.auto_dedup)
		pr_flags |= PR_MOD;
	if (pr_flags & PR_MOD)
		flags = O_RDWR;
	else
		flags = O_RSTR;

	switch (pr_flags & PR_TYPE_MASK) {
	case PR_TASK:
		i_typ = CR_FD_PAGEMAP;
		i_typ_o = CR_FD_PAGES_OLD;
		break;
	case PR_SHMEM:
		i_typ = CR_FD_SHMEM_PAGEMAP;
		i_typ_o = CR_FD_SHM_PAGES_OLD;
		break;
	default:
		BUG();
		return -1;
	}

	pr->pe = NULL;
	pr->parent = NULL;
	pr->bunch.iov_len = 0;
	pr->bunch.iov_base = NULL;

	pr->pmi = open_image_at(dfd, i_typ, O_RSTR, (long)pid);
	if (!pr->pmi)
		return -1;

	if (empty_image(pr->pmi)) {
		close_image(pr->pmi);
		goto open_old;
	}

	if ((i_typ != CR_FD_SHMEM_PAGEMAP) && try_open_parent(dfd, pid, pr, pr_flags)) {
		close_image(pr->pmi);
		return -1;
	}

	pr->pi = open_pages_image_at(dfd, flags, pr->pmi);
	if (!pr->pi) {
		close_page_read(pr);
		return -1;
	}

	pr->get_pagemap = get_pagemap;
	pr->put_pagemap = put_pagemap;
	pr->read_pages = read_pagemap_page;
	pr->close = close_page_read;
	pr->id = ids++;

	pr_debug("Opened page read %u (parent %u)\n",
			pr->id, pr->parent ? pr->parent->id : 0);

	return 1;

open_old:
	pr->pmi = open_image_at(dfd, i_typ_o, flags, pid);
	if (!pr->pmi)
		return -1;

	if (empty_image(pr->pmi)) {
		close_image(pr->pmi);
		return 0;
	}

	pr->get_pagemap = get_page_vaddr;
	pr->put_pagemap = NULL;
	pr->read_pages = read_page;
	pr->pi = NULL;
	pr->close = close_page_read;

	return 1;
}

int open_page_read(int pid, struct page_read *pr, int pr_flags)
{
	return open_page_read_at(get_service_fd(IMG_FD_OFF), pid, pr, pr_flags);
}
