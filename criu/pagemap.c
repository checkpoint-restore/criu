#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/falloc.h>

#include "image.h"
#include "cr_options.h"
#include "servicefd.h"
#include "pagemap.h"

#include "protobuf.h"
#include "images/pagemap.pb-c.h"

#ifndef SEEK_DATA
#define SEEK_DATA	3
#define SEEK_HOLE	4
#endif

#define MAX_BUNCH_SIZE 256

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

static inline bool can_extend_bunch(struct iovec *bunch,
		unsigned long off, unsigned long len)
{
	return  /* The next region is the continuation of the existing */
		((unsigned long)bunch->iov_base + bunch->iov_len == off) &&
		/* The resulting region is non empty and is small enough */
		(bunch->iov_len == 0 || bunch->iov_len + len < MAX_BUNCH_SIZE * PAGE_SIZE);
}

static int punch_hole(struct page_read *pr, unsigned long off,
		      unsigned long len, bool cleanup)
{
	int ret;
	struct iovec * bunch = &pr->bunch;

	if (!cleanup && can_extend_bunch(bunch, off, len)) {
		pr_debug("pr%d:Extend bunch len from %zu to %lu\n", pr->id,
			 bunch->iov_len, bunch->iov_len + len);
		bunch->iov_len += len;
	} else {
		if (bunch->iov_len > 0) {
			pr_debug("Punch!/%p/%zu/\n", bunch->iov_base, bunch->iov_len);
			ret = fallocate(img_raw_fd(pr->pi), FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
					(unsigned long)bunch->iov_base, bunch->iov_len);
			if (ret != 0) {
				pr_perror("Error punching hole");
				return -1;
			}
		}
		bunch->iov_base = (void *)off;
		bunch->iov_len = len;
		pr_debug("pr%d:New bunch/%p/%zu/\n", pr->id, bunch->iov_base, bunch->iov_len);
	}
	return 0;
}

int dedup_one_iovec(struct page_read *pr, struct iovec *iov)
{
	unsigned long off;
	unsigned long iov_end;

	iov_end = (unsigned long)iov->iov_base + iov->iov_len;
	off = (unsigned long)iov->iov_base;
	while (1) {
		int ret;
		struct iovec piov;
		unsigned long piov_end;
		struct iovec tiov;
		struct page_read * prp;

		ret = pr->seek_page(pr, off, false);
		if (ret == -1)
			return -1;

		if (ret == 0) {
			if (off < pr->cvaddr && pr->cvaddr < iov_end)
				off = pr->cvaddr;
			else
				return 0;
		}

		if (!pr->pe)
			return -1;
		pagemap2iovec(pr->pe, &piov);
		piov_end = (unsigned long)piov.iov_base + piov.iov_len;
		if (!pr->pe->in_parent) {
			ret = punch_hole(pr, pr->pi_off, min(piov_end, iov_end) - off, false);
			if (ret == -1)
				return ret;
		}

		prp = pr->parent;
		if (prp) {
			/* recursively */
			pr_debug("Go to next parent level\n");
			tiov.iov_base = (void*)off;
			tiov.iov_len = min(piov_end, iov_end) - off;
			ret = dedup_one_iovec(prp, &tiov);
			if (ret != 0)
				return -1;
		}

		if (piov_end < iov_end) {
			off = piov_end;
			continue;
		} else
			return 0;
	}
	return 0;
}

static int get_pagemap(struct page_read *pr, struct iovec *iov)
{
	PagemapEntry *pe;

	if (pr->curr_pme >= pr->nr_pmes)
		return 0;

	pe = pr->pmes[pr->curr_pme];

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
	pr->curr_pme++;
}

static void skip_pagemap_pages(struct page_read *pr, unsigned long len)
{
	if (!len)
		return;

	pr_debug("\tpr%u Skip %lu bytes from page-dump\n", pr->id, len);
	if (!pr->pe->in_parent)
		pr->pi_off += len;
	pr->cvaddr += len;
}

static int seek_pagemap_page(struct page_read *pr, unsigned long vaddr,
			     bool warn)
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
		off_t current_vaddr = lseek(fd, pr->pi_off, SEEK_SET);

		pr_debug("\tpr%u Read page from self %lx/%"PRIx64"\n", pr->id, pr->cvaddr, current_vaddr);
		ret = read(fd, buf, len);
		if (ret != len) {
			pr_perror("Can't read mapping page %d", ret);
			return -1;
		}

		pr->pi_off += len;

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

static void free_pagemaps(struct page_read *pr)
{
	int i;

	for (i = 0; i < pr->nr_pmes; i++)
		pagemap_entry__free_unpacked(pr->pmes[i], NULL);

	xfree(pr->pmes);
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

	if (pr->pmi)
		close_image(pr->pmi);
	if (pr->pi)
		close_image(pr->pi);

	if (pr->pmes)
		free_pagemaps(pr);
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

/*
 * The pagemap entry size is at least 8 bytes for small mappings with
 * low address and may get to 18 bytes or even more for large mappings
 * with high address and in_parent flag set. 16 seems to be nice round
 * number to minimize {over,under}-allocations
 */
#define PAGEMAP_ENTRY_SIZE_ESTIMATE 16

static int init_pagemaps(struct page_read *pr)
{
	off_t fsize;
	int nr_pmes, nr_realloc;

	fsize = img_raw_size(pr->pmi);
	if (fsize < 0)
		return -1;

	nr_pmes = fsize / PAGEMAP_ENTRY_SIZE_ESTIMATE + 1;
	nr_realloc = nr_pmes / 2;

	pr->pmes = xzalloc(nr_pmes * sizeof(*pr->pmes));
	if (!pr->pmes)
		return -1;

	pr->nr_pmes = pr->curr_pme = 0;

	while (1) {
		int ret = pb_read_one_eof(pr->pmi, &pr->pmes[pr->nr_pmes],
					  PB_PAGEMAP);
		if (ret < 0)
			goto free_pagemaps;
		if (ret == 0)
			break;

		pr->nr_pmes++;
		if (pr->nr_pmes >= nr_pmes) {
			nr_pmes += nr_realloc;
			pr->pmes = xrealloc(pr->pmes,
					    nr_pmes * sizeof(*pr->pmes));
			if (!pr->pmes)
				goto free_pagemaps;
		}
	}

	close_image(pr->pmi);
	pr->pmi = NULL;

	return 0;

free_pagemaps:
	free_pagemaps(pr);
	return -1;
}

int open_page_read_at(int dfd, int pid, struct page_read *pr, int pr_flags)
{
	int flags, i_typ;
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
		break;
	case PR_SHMEM:
		i_typ = CR_FD_SHMEM_PAGEMAP;
		break;
	default:
		BUG();
		return -1;
	}

	pr->pe = NULL;
	pr->parent = NULL;
	pr->cvaddr = 0;
	pr->pi_off = 0;
	pr->bunch.iov_len = 0;
	pr->bunch.iov_base = NULL;

	pr->pmi = open_image_at(dfd, i_typ, O_RSTR, (long)pid);
	if (!pr->pmi)
		return -1;

	if (empty_image(pr->pmi)) {
		close_image(pr->pmi);
		return 0;
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

	if (init_pagemaps(pr)) {
		close_page_read(pr);
		return -1;
	}

	pr->get_pagemap = get_pagemap;
	pr->put_pagemap = put_pagemap;
	pr->read_pages = read_pagemap_page;
	pr->close = close_page_read;
	pr->seek_page = seek_pagemap_page;
	pr->id = ids++;

	pr_debug("Opened page read %u (parent %u)\n",
			pr->id, pr->parent ? pr->parent->id : 0);

	return 1;
}

int open_page_read(int pid, struct page_read *pr, int pr_flags)
{
	return open_page_read_at(get_service_fd(IMG_FD_OFF), pid, pr, pr_flags);
}
