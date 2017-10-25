#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/falloc.h>
#include <sys/uio.h>
#include <limits.h>

#include "types.h"
#include "image.h"
#include "cr_options.h"
#include "servicefd.h"
#include "pagemap.h"
#include "restorer.h"
#include "rst-malloc.h"
#include "page-xfer.h"

#include "fault-injection.h"
#include "xmalloc.h"
#include "protobuf.h"
#include "images/pagemap.pb-c.h"

#ifndef SEEK_DATA
#define SEEK_DATA	3
#define SEEK_HOLE	4
#endif

#define MAX_BUNCH_SIZE 256

/*
 * One "job" for the preadv() syscall in pagemap.c
 */
struct page_read_iov {
	off_t from;		/* offset in pi file where to start reading from */
	off_t end;		/* the end of the read == sum to.iov_len -s */
	struct iovec *to;	/* destination iovs */
	unsigned int nr;	/* their number */

	struct list_head l;
};

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
		pr_debug("pr%lu-%u:Extend bunch len from %zu to %lu\n", pr->img_id,
			 pr->id, bunch->iov_len, bunch->iov_len + len);
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
		pr_debug("pr%lu-%u:New bunch/%p/%zu/\n", pr->img_id, pr->id, bunch->iov_base, bunch->iov_len);
	}
	return 0;
}

int dedup_one_iovec(struct page_read *pr, unsigned long off, unsigned long len)
{
	unsigned long iov_end;

	iov_end = off + len;
	while (1) {
		int ret;
		unsigned long piov_end;
		struct page_read * prp;

		ret = pr->seek_pagemap(pr, off);
		if (ret == 0) {
			pr_warn("Missing %lx in parent pagemap\n", off);
			if (off < pr->cvaddr && pr->cvaddr < iov_end)
				off = pr->cvaddr;
			else
				return 0;
		}

		if (!pr->pe)
			return -1;
		piov_end = pr->pe->vaddr + pagemap_len(pr->pe);
		if (!pagemap_in_parent(pr->pe)) {
			ret = punch_hole(pr, pr->pi_off, min(piov_end, iov_end) - off, false);
			if (ret == -1)
				return ret;
		}

		prp = pr->parent;
		if (prp) {
			/* recursively */
			pr_debug("Go to next parent level\n");
			len = min(piov_end, iov_end) - off;
			ret = dedup_one_iovec(prp, off, len);
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

static int advance(struct page_read *pr)
{
	pr->curr_pme++;
	if (pr->curr_pme >= pr->nr_pmes)
		return 0;

	pr->pe = pr->pmes[pr->curr_pme];
	pr->cvaddr = pr->pe->vaddr;

	return 1;
}

static void skip_pagemap_pages(struct page_read *pr, unsigned long len)
{
	if (!len)
		return;

	if (pagemap_present(pr->pe))
		pr->pi_off += len;
	pr->cvaddr += len;
}

static int seek_pagemap(struct page_read *pr, unsigned long vaddr)
{
	if (!pr->pe)
		goto adv;

	do {
		unsigned long start = pr->pe->vaddr;
		unsigned long len = pr->pe->nr_pages * PAGE_SIZE;
		unsigned long end = start + len;

		if (vaddr < pr->cvaddr)
			break;

		if (vaddr >= start && vaddr < end) {
			skip_pagemap_pages(pr, vaddr - pr->cvaddr);
			return 1;
		}

		if (end <= vaddr)
			skip_pagemap_pages(pr, end - pr->cvaddr);
adv:
		; /* otherwise "label at end of compound stmt" gcc error */
	} while (advance(pr));

	return 0;
}

static inline void pagemap_bound_check(PagemapEntry *pe, unsigned long vaddr, int nr)
{
	if (vaddr < pe->vaddr || (vaddr - pe->vaddr) / PAGE_SIZE + nr > pe->nr_pages) {
		pr_err("Page read err %"PRIx64":%u vs %lx:%u\n",
				pe->vaddr, pe->nr_pages, vaddr, nr);
		BUG();
	}
}

static int read_parent_page(struct page_read *pr, unsigned long vaddr,
			    int nr, void *buf, unsigned flags)
{
	struct page_read *ppr = pr->parent;
	int ret;

	if (!ppr) {
		pr_err("No parent for snapshot pagemap\n");
		return -1;
	}

	/*
	 * Parent pagemap at this point entry may be shorter
	 * than the current vaddr:nr needs, so we have to
	 * carefully 'split' the vaddr:nr into pieces and go
	 * to parent page-read with the longest requests it
	 * can handle.
	 */

	do {
		int p_nr;

		pr_debug("\tpr%lu-%u Read from parent\n", pr->img_id, pr->id);
		ret = ppr->seek_pagemap(ppr, vaddr);
		if (ret <= 0) {
			pr_err("Missing %lx in parent pagemap\n", vaddr);
			return -1;
		}

		/*
		 * This is how many pages we have in the parent
		 * page_read starting from vaddr. Go ahead and
		 * read as much as we can.
		 */
		p_nr = ppr->pe->nr_pages - (vaddr - ppr->pe->vaddr) / PAGE_SIZE;
		pr_info("\tparent has %u pages in\n", p_nr);
		if (p_nr > nr)
			p_nr = nr;

		ret = ppr->read_pages(ppr, vaddr, p_nr, buf, flags);
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

	return 0;
}

static int read_local_page(struct page_read *pr, unsigned long vaddr,
			   unsigned long len, void *buf)
{
	int fd = img_raw_fd(pr->pi);
	int ret;
	size_t curr = 0;

	/*
	 * Flush any pending async requests if any not to break the
	 * linear reading from the pages.img file.
	 */
	if (pr->sync(pr))
		return -1;

	pr_debug("\tpr%lu-%u Read page from self %lx/%"PRIx64"\n", pr->img_id, pr->id, pr->cvaddr, pr->pi_off);
	while (1) {
		ret = pread(fd, buf + curr, len - curr, pr->pi_off + curr);
		if (ret < 1) {
			pr_perror("Can't read mapping page %d", ret);
			return -1;
		}
		curr += ret;
		if (curr == len)
			break;
	}

	if (opts.auto_dedup) {
		ret = punch_hole(pr, pr->pi_off, len, false);
		if (ret == -1)
			return -1;
	}

	return 0;
}

static int enqueue_async_iov(struct page_read *pr, void *buf,
		unsigned long len, struct list_head *to)
{
	struct page_read_iov *pr_iov;
	struct iovec *iov;

	pr_iov = xzalloc(sizeof(*pr_iov));
	if (!pr_iov)
		return -1;

	pr_iov->from = pr->pi_off;
	pr_iov->end = pr->pi_off + len;

	iov = xzalloc(sizeof(*iov));
	if (!iov) {
		xfree(pr_iov);
		return -1;
	}

	iov->iov_base = buf;
	iov->iov_len = len;

	pr_iov->to = iov;
	pr_iov->nr = 1;

	list_add_tail(&pr_iov->l, to);

	return 0;
}

int pagemap_render_iovec(struct list_head *from, struct task_restore_args *ta)
{
	struct page_read_iov *piov;

	ta->vma_ios = (struct restore_vma_io *)rst_mem_align_cpos(RM_PRIVATE);
	ta->vma_ios_n = 0;

	list_for_each_entry(piov, from, l) {
		struct restore_vma_io *rio;

		pr_info("`- render %d iovs (%p:%zd...)\n", piov->nr,
				piov->to[0].iov_base, piov->to[0].iov_len);
		rio = rst_mem_alloc(RIO_SIZE(piov->nr), RM_PRIVATE);
		if (!rio)
			return -1;

		rio->nr_iovs = piov->nr;
		rio->off = piov->from;
		memcpy(rio->iovs, piov->to, piov->nr * sizeof(struct iovec));

		ta->vma_ios_n++;
	}

	return 0;
}

int pagemap_enqueue_iovec(struct page_read *pr, void *buf,
			      unsigned long len, struct list_head *to)
{
	struct page_read_iov *cur_async = NULL;
	struct iovec *iov;

	if (!list_empty(to))
		cur_async = list_entry(to->prev, struct page_read_iov, l);

	/*
	 * We don't have any async requests or we have new read
	 * request that should happen at pos _after_ some hole from
	 * the previous one.
	 * Start the new preadv request here.
	 */
	if (!cur_async || pr->pi_off != cur_async->end)
		return enqueue_async_iov(pr, buf, len, to);

	/*
	 * This read is pure continuation of the previous one. Let's
	 * just add another IOV (or extend one of the existing).
	 */
	iov = &cur_async->to[cur_async->nr - 1];
	if (iov->iov_base + iov->iov_len == buf) {
		/* Extendable */
		iov->iov_len += len;
	} else {
		/* Need one more target iovec */
		unsigned int n_iovs = cur_async->nr + 1;

		if (n_iovs >= IOV_MAX)
			return enqueue_async_iov(pr, buf, len, to);

		iov = xrealloc(cur_async->to, n_iovs * sizeof(*iov));
		if (!iov)
			return -1;

		cur_async->to = iov;

		iov += cur_async->nr;
		iov->iov_base = buf;
		iov->iov_len = len;

		cur_async->nr = n_iovs;
	}

	cur_async->end += len;

	return 0;
}

static int maybe_read_page_local(struct page_read *pr, unsigned long vaddr,
				 int nr, void *buf, unsigned flags)
{
	int ret;
	unsigned long len = nr * PAGE_SIZE;

	/*
	 * There's no API in the kernel to start asynchronous
	 * cached read (or write), so in case someone is asking
	 * for us for urgent async read, just do the regular
	 * cached read.
	 */
	if ((flags & (PR_ASYNC|PR_ASAP)) == PR_ASYNC)
		ret = pagemap_enqueue_iovec(pr, buf, len, &pr->async);
	else {
		ret = read_local_page(pr, vaddr, len, buf);
		if (ret == 0 && pr->io_complete)
			ret = pr->io_complete(pr, vaddr, nr);
	}

	pr->pi_off += len;

	return ret;
}

static int read_page_complete(unsigned long img_id, unsigned long vaddr, int nr_pages, void *priv)
{
	int ret = 0;
	struct page_read *pr = priv;

	if (pr->img_id != img_id) {
		pr_err("Out of order read completed (want %lu have %lu)\n",
				pr->img_id, img_id);
		return -1;
	}

	if (pr->io_complete)
		ret = pr->io_complete(pr, vaddr, nr_pages);

	return ret;
}

static int maybe_read_page_remote(struct page_read *pr, unsigned long vaddr,
				  int nr, void *buf, unsigned flags)
{
	int ret;

	/* We always do PR_ASAP mode here (FIXME?) */
	ret = request_remote_pages(pr->img_id, vaddr, nr);
	if (!ret)
		ret = page_server_start_read(buf, nr,
				read_page_complete, pr, flags);
	return ret;
}

static int read_pagemap_page(struct page_read *pr, unsigned long vaddr, int nr,
			     void *buf, unsigned flags)
{
	pr_info("pr%lu-%u Read %lx %u pages\n", pr->img_id, pr->id, vaddr, nr);
	pagemap_bound_check(pr->pe, vaddr, nr);

	if (pagemap_in_parent(pr->pe)) {
		if (read_parent_page(pr, vaddr, nr, buf, flags) < 0)
			return -1;
	} else {
		if (pr->maybe_read_page(pr, vaddr, nr, buf, flags) < 0)
			return -1;
	}

	pr->cvaddr += nr * PAGE_SIZE;

	return 1;
}

static void free_pagemaps(struct page_read *pr)
{
	int i;

	for (i = 0; i < pr->nr_pmes; i++)
		pagemap_entry__free_unpacked(pr->pmes[i], NULL);

	xfree(pr->pmes);
}

static void advance_piov(struct page_read_iov *piov, ssize_t len)
{
	ssize_t olen = len;
	int onr = piov->nr;
	piov->from += len;

	while (len) {
		struct iovec *cur = piov->to;

		if (cur->iov_len <= len) {
			piov->to++;
			piov->nr--;
			len -= cur->iov_len;
			continue;
		}

		cur->iov_base += len;
		cur->iov_len -= len;
		break;
	}

	pr_debug("Advanced iov %zu bytes, %d->%d iovs, %zu tail\n",
			olen, onr, piov->nr, len);
}

static int process_async_reads(struct page_read *pr)
{
	int fd, ret = 0;
	struct page_read_iov *piov, *n;

	fd = img_raw_fd(pr->pi);
	list_for_each_entry_safe(piov, n, &pr->async, l) {
		ssize_t ret;
		off_t start = piov->from;
		struct iovec *iovs = piov->to;

		pr_debug("Read piov iovs %d, from %ju, len %ju, first %p:%zu\n",
				piov->nr, piov->from, piov->end - piov->from,
				piov->to->iov_base, piov->to->iov_len);
more:
		ret = preadv(fd, piov->to, piov->nr, piov->from);
		if (fault_injected(FI_PARTIAL_PAGES)) {
			/*
			 * We might have read everything, but for debug
			 * purposes let's try to force the advance_piov()
			 * and re-read tail.
			 */
			if (ret > 0 && piov->nr >= 2) {
				pr_debug("`- trim preadv %zu\n", ret);
				ret /= 2;
			}
		}

		if (ret != piov->end - piov->from) {
			if (ret < 0) {
				pr_err("Can't read async pr bytes (%zd / %ju read, %ju off, %d iovs)\n",
						ret, piov->end - piov->from, piov->from, piov->nr);
				return -1;
			}

			/*
			 * The preadv() can return less than requested. It's
			 * valid and doesn't mean error or EOF. We should advance
			 * the iovecs and continue
			 *
			 * Modify the piov in-place, we're going to drop this one
			 * anyway.
			 */

			advance_piov(piov, ret);
			goto more;
		}

		if (opts.auto_dedup && punch_hole(pr, start, ret, false))
			return -1;

		BUG_ON(pr->io_complete); /* FIXME -- implement once needed */

		list_del(&piov->l);
		xfree(iovs);
		xfree(piov);
	}

	if (pr->parent)
		ret = process_async_reads(pr->parent);

	return ret;
}

static void close_page_read(struct page_read *pr)
{
	int ret;

	BUG_ON(!list_empty(&pr->async));

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

static void reset_pagemap(struct page_read *pr)
{
	pr->cvaddr = 0;
	pr->pi_off = 0;
	pr->curr_pme = -1;
	pr->pe = NULL;

	/* FIXME: take care of bunch */

	if (pr->parent)
		reset_pagemap(pr->parent);
}

static int try_open_parent(int dfd, unsigned long id, struct page_read *pr, int pr_flags)
{
	int pfd, ret;
	struct page_read *parent = NULL;

	pfd = openat(dfd, CR_PARENT_LINK, O_RDONLY);
	if (pfd < 0 && errno == ENOENT)
		goto out;

	parent = xmalloc(sizeof(*parent));
	if (!parent)
		goto err_cl;

	ret = open_page_read_at(pfd, id, parent, pr_flags);
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

static void init_compat_pagemap_entry(PagemapEntry *pe)
{
	/*
	 * pagemap image generated with older version will either
	 * contain a hole because the pages are in the parent
	 * shanpshot or a pagemap that should be marked with
	 * PE_PRESENT
	 */
	if (pe->has_in_parent && pe->in_parent)
		pe->flags |= PE_PARENT;
	else if (!pe->has_flags)
		pe->flags = PE_PRESENT;
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

	pr->nr_pmes = 0;
	pr->curr_pme = -1;

	while (1) {
		int ret = pb_read_one_eof(pr->pmi, &pr->pmes[pr->nr_pmes],
					  PB_PAGEMAP);
		if (ret < 0)
			goto free_pagemaps;
		if (ret == 0)
			break;

		init_compat_pagemap_entry(pr->pmes[pr->nr_pmes]);

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

int open_page_read_at(int dfd, unsigned long img_id, struct page_read *pr, int pr_flags)
{
	int flags, i_typ;
	static unsigned ids = 1;
	bool remote = pr_flags & PR_REMOTE;

	/*
	 * Only the top-most page-read can be remote, all the
	 * others are always local.
	 */
	pr_flags &= ~PR_REMOTE;
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

	INIT_LIST_HEAD(&pr->async);
	pr->pe = NULL;
	pr->parent = NULL;
	pr->cvaddr = 0;
	pr->pi_off = 0;
	pr->bunch.iov_len = 0;
	pr->bunch.iov_base = NULL;
	pr->pmes = NULL;
	pr->pieok = false;

	pr->pmi = open_image_at(dfd, i_typ, O_RSTR, img_id);
	if (!pr->pmi)
		return -1;

	if (empty_image(pr->pmi)) {
		close_image(pr->pmi);
		return 0;
	}

	if (try_open_parent(dfd, img_id, pr, pr_flags)) {
		close_image(pr->pmi);
		return -1;
	}

	pr->pi = open_pages_image_at(dfd, flags, pr->pmi, &pr->pages_img_id);
	if (!pr->pi) {
		close_page_read(pr);
		return -1;
	}

	if (init_pagemaps(pr)) {
		close_page_read(pr);
		return -1;
	}

	pr->read_pages = read_pagemap_page;
	pr->advance = advance;
	pr->close = close_page_read;
	pr->skip_pages = skip_pagemap_pages;
	pr->sync = process_async_reads;
	pr->seek_pagemap = seek_pagemap;
	pr->reset = reset_pagemap;
	pr->io_complete = NULL; /* set up by the client if needed */
	pr->id = ids++;
	pr->img_id = img_id;

	if (remote)
		pr->maybe_read_page = maybe_read_page_remote;
	else {
		pr->maybe_read_page = maybe_read_page_local;
		if (!pr->parent && !opts.lazy_pages)
			pr->pieok = true;
	}

	pr_debug("Opened %s page read %u (parent %u)\n",
		 remote ? "remote" : "local", pr->id,
		 pr->parent ? pr->parent->id : 0);

	return 1;
}

int open_page_read(unsigned long img_id, struct page_read *pr, int pr_flags)
{
	return open_page_read_at(get_service_fd(IMG_FD_OFF), img_id, pr, pr_flags);
}


#define DUP_IDS_BASE 1000

void dup_page_read(struct page_read *src, struct page_read *dst)
{
	static int dup_ids = 1;

	memcpy(dst, src, sizeof(*dst));
	INIT_LIST_HEAD(&dst->async);
	dst->id = src->id + DUP_IDS_BASE * dup_ids++;
	dst->reset(dst);
}
