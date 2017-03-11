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
		     unsigned int nr_segs, unsigned int flags,
		     struct iovec *iov)
{
	ppb->pages_in = pages_in;
	ppb->nr_segs = nr_segs;
	ppb->flags = flags;
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

static struct page_pipe_buf *ppb_alloc_resize(struct page_pipe *pp, int size)
{
	struct page_pipe_buf *ppb;
	int nr_pages = size / PAGE_SIZE;

	ppb = ppb_alloc(pp);
	if (!ppb)
		return NULL;

	if (ppb->pipe_size < nr_pages) {
		if (ppb_resize_pipe(ppb, nr_pages)) {
			ppb_destroy(ppb);
			return NULL;
		}
	}

	return ppb;
}

static int page_pipe_grow(struct page_pipe *pp, unsigned int flags)
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
	ppb_init(ppb, 0, 0, flags, free_iov);

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

	if (page_pipe_grow(pp, 0))
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

	if (page_pipe_grow(pp, 0))
		BUG(); /* It can't fail, because ppb is in free_bufs */
}

static inline int try_add_page_to(struct page_pipe *pp, struct page_pipe_buf *ppb,
		unsigned long addr, unsigned int flags)
{
	if (ppb->flags != flags)
		return 1;

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

static inline int try_add_page(struct page_pipe *pp, unsigned long addr,
			       unsigned int flags)
{
	BUG_ON(list_empty(&pp->bufs));
	return try_add_page_to(pp, list_entry(pp->bufs.prev, struct page_pipe_buf, l), addr, flags);
}

int page_pipe_add_page(struct page_pipe *pp, unsigned long addr,
		       unsigned int flags)
{
	int ret;

	ret = try_add_page(pp, addr, flags);
	if (ret <= 0)
		return ret;

	ret = page_pipe_grow(pp, flags);
	if (ret < 0)
		return ret;

	ret = try_add_page(pp, addr, flags);
	BUG_ON(ret > 0);
	return ret;
}

#define PP_HOLES_BATCH	32

int page_pipe_add_hole(struct page_pipe *pp, unsigned long addr,
		       unsigned int flags)
{
	if (pp->free_hole >= pp->nr_holes) {
		pp->holes = xrealloc(pp->holes,
				(pp->nr_holes + PP_HOLES_BATCH) * sizeof(struct iovec));
		if (!pp->holes)
			return -1;

		pp->hole_flags = xrealloc(pp->hole_flags,
					  (pp->nr_holes + PP_HOLES_BATCH) * sizeof(unsigned int));
		if(!pp->hole_flags)
			return -1;

		pp->nr_holes += PP_HOLES_BATCH;
	}

	if (pp->free_hole &&
	    pp->hole_flags[pp->free_hole - 1] == flags &&
	    iov_grow_page(&pp->holes[pp->free_hole - 1], addr))
		goto out;

	iov_init(&pp->holes[pp->free_hole++], addr);

	pp->hole_flags[pp->free_hole - 1] = flags;

out:
	return 0;
}

/*
 * Get ppb and iov that contain addr and count amount of data between
 * beginning of the pipe belonging to the ppb and addr
 */
static struct page_pipe_buf *get_ppb(struct page_pipe *pp, unsigned long addr,
				     struct iovec **iov_ret,
				     unsigned long *len)
{
	struct page_pipe_buf *ppb;
	int i;

	list_for_each_entry(ppb, &pp->bufs, l) {
		for (i = 0, *len = 0; i < ppb->nr_segs; i++) {
			struct iovec *iov = &ppb->iov[i];
			unsigned long base = (unsigned long)iov->iov_base;

			if (addr < base || addr >= base + iov->iov_len) {
				*len += iov->iov_len;
				continue;
			}

			/* got iov that contains the addr */
			*len += (addr - base);
			*iov_ret = iov;

			list_move(&ppb->l, &pp->bufs);
			return ppb;
		}
	}

	return NULL;
}

static int page_pipe_split_iov(struct page_pipe *pp, struct page_pipe_buf *ppb,
			       struct iovec *iov, unsigned long addr,
			       bool popup_new)
{
	unsigned long len = addr - (unsigned long)iov->iov_base;
	struct page_pipe_buf *ppb_new;
	struct iovec *iov_new;
	int ret;

	if (len == iov->iov_len)
		return 0;

	ppb_new = ppb_alloc_resize(pp, len);
	if (!ppb_new)
		return -1;

	ret = splice(ppb->p[0], NULL, ppb_new->p[1], NULL, len, SPLICE_F_MOVE);
	if (ret != len)
		return -1;

	iov_new = &pp->iovs[pp->free_iov++];
	BUG_ON(pp->free_iov > pp->nr_iovs);
	iov_new->iov_base = iov->iov_base;
	iov_new->iov_len = len;

	ppb_init(ppb_new, len / PAGE_SIZE, 1, ppb->flags, iov_new);

	ppb->pages_in -= len / PAGE_SIZE;

	iov->iov_base += len;
	iov->iov_len -= len;

	if (popup_new)
		ppb = ppb_new;
	list_move(&ppb->l, &pp->bufs);

	return 0;
}

static int page_pipe_split_ppb(struct page_pipe *pp, struct page_pipe_buf *ppb,
			       struct iovec *iov, unsigned long len,
			       bool popup_new)
{
	struct page_pipe_buf *ppb_new;
	int ret;

	ppb_new = ppb_alloc_resize(pp, len);
	if (!ppb_new)
		return -1;

	ret = splice(ppb->p[0], NULL, ppb_new->p[1], NULL, len, SPLICE_F_MOVE);
	if (ret != len)
		return -1;

	ppb_init(ppb_new, len / PAGE_SIZE, iov - ppb->iov, ppb->flags, ppb->iov);

	ppb->iov += ppb_new->nr_segs;
	ppb->nr_segs -= ppb_new->nr_segs;
	ppb->pages_in -= len / PAGE_SIZE;

	if (popup_new)
		ppb = ppb_new;
	list_move(&ppb->l, &pp->bufs);

	return 0;
}

/*
 * Find the ppb containing addr and split so that we can splice
 * nr_pages starting from addr. Make the ppb containing relavant pages
 * the first entry in bb->bufs list
 */
int page_pipe_split(struct page_pipe *pp, unsigned long addr,
		    unsigned int *nr_pages)
{
	struct page_pipe_buf *ppb;
	struct iovec *iov = NULL;
	unsigned long len = 0;
	int ret;

	/*
	 * Get ppb that contains addr and count length of data between
	 * the beginning of the pipe and addr. If no ppb is found, the
	 * requested page is mapped to zero pfn
	 */
	ppb = get_ppb(pp, addr, &iov, &len);
	if (!ppb) {
		*nr_pages = 0;
		return 0;
	}

	/*
	 * Split origingal ppb on boundary of iov that contains
	 * addr. The ppb containing the address will remain at the
	 * pp->buf list head.
	 */
	if (iov != ppb->iov) {
		len -= (addr - (unsigned long)iov->iov_base);
		ret = page_pipe_split_ppb(pp, ppb, iov, len, false);
		if (ret)
			return -1;
	}

	/*
	 * Split the tail of the ppb. We presume that requests do not
	 * cross IOV (that is pagemap entry) boundaries.
	 * The newly created ppb will contain the desired IOV and will
	 * be poped to the head of the pp->buf list
	 */
	if (ppb->nr_segs > 1) {
		len = iov->iov_len;
		ret = page_pipe_split_ppb(pp, ppb, iov + 1, len, true);
		if (ret)
			return -1;
		ppb = list_first_entry(&pp->bufs, struct page_pipe_buf, l);
	}

	/*
	 * if address does not match iov base, split the iov and
	 * create a new ppb pointing to the new iov
	 */
	if (addr != (unsigned long)iov->iov_base) {
		ret = page_pipe_split_iov(pp, ppb, iov, addr, false);
		if (ret)
			return -1;
	}

	/*
	 * at this point iov_base points to addr, so we need to split
	 * the part after addr + requested pages to a separate iov
	 */
	len = min((unsigned long)iov->iov_base + iov->iov_len - addr,
		  (unsigned long)(*nr_pages) * PAGE_SIZE);
	ret = page_pipe_split_iov(pp, ppb, iov, addr + len, true);
	if (ret)
		return -1;

	*nr_pages = len / PAGE_SIZE;

	return 0;
}

void page_pipe_destroy_ppb(struct page_pipe_buf *ppb)
{
	list_del(&ppb->l);
	ppb_destroy(ppb);
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
		pr_debug("\tbuf %u pages, %u iovs, flags: %x :\n",
			 ppb->pages_in, ppb->nr_segs, ppb->flags);
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
