#include <unistd.h>

#undef LOG_PREFIX
#define LOG_PREFIX "page-pipe: "

#include "page.h"
#include "config.h"
#include "util.h"
#include "criu-log.h"
#include "page-pipe.h"
#include "fcntl.h"

/* can existing iov accumulate the page? */
static inline bool iov_grow_page(struct iovec *iov, unsigned long addr)
{
	if ((unsigned long)iov->iov_base + iov->iov_len == addr) {
		iov->iov_len += PAGE_SIZE;
		return true;
	}

	return false;
}

static inline void iov_init(struct iovec *iov, unsigned long addr)
{
	iov->iov_base = (void *)addr;
	iov->iov_len = PAGE_SIZE;
}

static struct page_pipe_buf *ppb_alloc(struct page_pipe *pp)
{
	struct page_pipe_buf *ppb;

	ppb = xmalloc(sizeof(*ppb));
	if (!ppb)
		return NULL;

	if (pipe(ppb->p)) {
		xfree(ppb);
		pr_perror("Can't make pipe for page-pipe");
		return NULL;
	}

	ppb->pipe_size = fcntl(ppb->p[0], F_GETPIPE_SZ, 0) / PAGE_SIZE;
	pp->nr_pipes++;

	list_add_tail(&ppb->l, &pp->bufs);

	return ppb;
}

static void ppb_destroy(struct page_pipe_buf *ppb)
{
	close(ppb->p[0]);
	close(ppb->p[1]);
	xfree(ppb);
}

static void ppb_init(struct page_pipe_buf *ppb, unsigned int pages_in,
		     unsigned int nr_segs, struct iovec *iov)
{
	ppb->pages_in = pages_in;
	ppb->nr_segs = nr_segs;
	ppb->iov = iov;
}

static int ppb_resize_pipe(struct page_pipe_buf *ppb, unsigned long new_size)
{
	int ret;

	ret = fcntl(ppb->p[0], F_SETPIPE_SZ, new_size * PAGE_SIZE);
	if (ret < 0)
		return -1;

	ret /= PAGE_SIZE;
	BUG_ON(ret < ppb->pipe_size);

	pr_debug("Grow pipe %x -> %x\n", ppb->pipe_size, ret);
	ppb->pipe_size = ret;

	return 0;
}

static int page_pipe_grow(struct page_pipe *pp)
{
	struct page_pipe_buf *ppb;
	struct iovec *free_iov;

	pr_debug("Will grow page pipe (iov off is %u)\n", pp->free_iov);

	if (!list_empty(&pp->free_bufs)) {
		ppb = list_first_entry(&pp->free_bufs, struct page_pipe_buf, l);
		list_move_tail(&ppb->l, &pp->bufs);
		goto out;
	}

	if ((pp->flags & PP_CHUNK_MODE) && (pp->nr_pipes == NR_PIPES_PER_CHUNK))
		return -EAGAIN;

	ppb = ppb_alloc(pp);
	if (!ppb)
		return -1;

out:
	free_iov = &pp->iovs[pp->free_iov];
	ppb_init(ppb, 0, 0, free_iov);

	return 0;
}

struct page_pipe *create_page_pipe(unsigned int nr_segs, struct iovec *iovs, unsigned flags)
{
	struct page_pipe *pp;

	pr_debug("Create page pipe for %u segs\n", nr_segs);

	pp = xzalloc(sizeof(*pp));
	if (!pp)
		return NULL;

	pp->flags = flags;

	if (!iovs) {
		iovs = xmalloc(sizeof(*iovs) * nr_segs);
		if (!iovs)
			goto err_free_pp;

		pp->flags |= PP_OWN_IOVS;
	}

	pp->nr_pipes = 0;
	INIT_LIST_HEAD(&pp->bufs);
	INIT_LIST_HEAD(&pp->free_bufs);
	pp->nr_iovs = nr_segs;
	pp->iovs = iovs;
	pp->free_iov = 0;

	pp->nr_holes = 0;
	pp->free_hole = 0;
	pp->holes = NULL;

	if (page_pipe_grow(pp))
		goto err_free_iovs;

	return pp;

err_free_iovs:
	if (pp->flags & PP_OWN_IOVS)
		xfree(iovs);
err_free_pp:
	xfree(pp);
	return NULL;
}

void destroy_page_pipe(struct page_pipe *pp)
{
	struct page_pipe_buf *ppb, *n;

	pr_debug("Killing page pipe\n");

	list_splice(&pp->free_bufs, &pp->bufs);
	list_for_each_entry_safe(ppb, n, &pp->bufs, l)
		ppb_destroy(ppb);

	if (pp->flags & PP_OWN_IOVS)
		xfree(pp->iovs);
	xfree(pp);
}

void page_pipe_reinit(struct page_pipe *pp)
{
	struct page_pipe_buf *ppb, *n;

	BUG_ON(!(pp->flags & PP_CHUNK_MODE));

	pr_debug("Clean up page pipe\n");

	list_for_each_entry_safe(ppb, n, &pp->bufs, l)
		list_move(&ppb->l, &pp->free_bufs);

	pp->free_hole = 0;

	if (page_pipe_grow(pp))
		BUG(); /* It can't fail, because ppb is in free_bufs */
}

static inline int try_add_page_to(struct page_pipe *pp, struct page_pipe_buf *ppb,
		unsigned long addr)
{
	if (ppb->pages_in == ppb->pipe_size) {
		unsigned long new_size = ppb->pipe_size << 1;
		int ret;

		if (new_size > PIPE_MAX_SIZE)
			return 1;

		ret = ppb_resize_pipe(ppb, new_size);
		if (ret < 0)
			return 1; /* need to add another buf */
	}

	if (ppb->nr_segs) {
		if (iov_grow_page(&ppb->iov[ppb->nr_segs - 1], addr))
			goto out;

		if (ppb->nr_segs == UIO_MAXIOV)
			/* XXX -- shrink pipe back? */
			return 1;
	}

	pr_debug("Add iov to page pipe (%u iovs, %u/%u total)\n",
			ppb->nr_segs, pp->free_iov, pp->nr_iovs);
	iov_init(&ppb->iov[ppb->nr_segs++], addr);
	pp->free_iov++;
	BUG_ON(pp->free_iov > pp->nr_iovs);
out:
	ppb->pages_in++;
	return 0;
}

static inline int try_add_page(struct page_pipe *pp, unsigned long addr)
{
	BUG_ON(list_empty(&pp->bufs));
	return try_add_page_to(pp, list_entry(pp->bufs.prev, struct page_pipe_buf, l), addr);
}

int page_pipe_add_page(struct page_pipe *pp, unsigned long addr)
{
	int ret;

	ret = try_add_page(pp, addr);
	if (ret <= 0)
		return ret;

	ret = page_pipe_grow(pp);
	if (ret < 0)
		return ret;

	ret = try_add_page(pp, addr);
	BUG_ON(ret > 0);
	return ret;
}

#define PP_HOLES_BATCH	32

int page_pipe_add_hole(struct page_pipe *pp, unsigned long addr)
{
	if (pp->free_hole >= pp->nr_holes) {
		pp->holes = xrealloc(pp->holes,
				(pp->nr_holes + PP_HOLES_BATCH) * sizeof(struct iovec));
		if (!pp->holes)
			return -1;

		pp->nr_holes += PP_HOLES_BATCH;
	}

	if (pp->free_hole &&
			iov_grow_page(&pp->holes[pp->free_hole - 1], addr))
		goto out;

	iov_init(&pp->holes[pp->free_hole++], addr);

out:
	return 0;
}

void debug_show_page_pipe(struct page_pipe *pp)
{
	struct page_pipe_buf *ppb;
	int i;
	struct iovec *iov;

	if (pr_quelled(LOG_DEBUG))
		return;

	pr_debug("Page pipe:\n");
	pr_debug("* %u pipes %u/%u iovs:\n",
			pp->nr_pipes, pp->free_iov, pp->nr_iovs);
	list_for_each_entry(ppb, &pp->bufs, l) {
		pr_debug("\tbuf %u pages, %u iovs:\n",
				ppb->pages_in, ppb->nr_segs);
		for (i = 0; i < ppb->nr_segs; i++) {
			iov = &ppb->iov[i];
			pr_debug("\t\t%p %lu\n", iov->iov_base,
					iov->iov_len / PAGE_SIZE);
		}
	}

	pr_debug("* %u holes:\n", pp->free_hole);
	for (i = 0; i < pp->free_hole; i++) {
		iov = &pp->holes[i];
		pr_debug("\t%p %lu\n", iov->iov_base, iov->iov_len / PAGE_SIZE);
	}
}
