#ifndef __CR_PAGE_READ_H__
#define __CR_PAGE_READ_H__

#include <stddef.h>
#include <sys/types.h>

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

struct encoded_read_ctx;

struct page_read {
	/* reads page from current pagemap */
	int (*read_pages)(struct page_read *, unsigned long vaddr, unsigned long nr, void *, unsigned flags);

	/* Advance page_read to the next entry */
	int (*advance)(struct page_read *pr);

	/* Close all images: pagemap, pages (both local & parent) */
	void (*close)(struct page_read *);

	/* Advance virtual and pages-image cursors without copying data */
	void (*skip_pages)(struct page_read *, unsigned long len);

	/* Process and drain queued asynchronous page reads */
	int (*sync)(struct page_read *pr);

	/* Reposition read file offset for specific vaddr */
	int (*seek_pagemap)(struct page_read *pr, unsigned long vaddr);

	/* Reset read cursors and current entries, including parent readers */
	void (*reset)(struct page_read *pr);

	/* Used only for lazy restore (= uffd_io_complete) */
	int (*io_complete)(struct page_read *, unsigned long vaddr, unsigned long nr);

	/* Read from the selected remote, streamed, or local backing image */
	int (*maybe_read_page)(struct page_read *pr, unsigned long vaddr, unsigned long nr, void *buf, unsigned flags);

	/* Whether or not pages can be read in PIE code (restorer context) */
	bool pieok;

	/* Whether or not disable image deduplication*/
	bool disable_dedup;

	/* Whether O_DIRECT is active on the pages fd. Set once during
	 * open_page_read_at() after probing that direct reads work; never changes after
	 * that. Cached here to avoid a fcntl(F_GETFL) syscall per page read. */
	bool use_direct;

	/* Private data of reader */
	struct cr_img *pmi;
	struct cr_img *pi;
	u32 pages_img_id;

	/* Current pagemap we are on */
	PagemapEntry *pe;

	/* Parent pagemap (if ->in_parent pagemap is met in image,
	 * then go to this guy for page, see read_pagemap_page) */
	struct page_read *parent;

	/* Current virtual address we are on */
	unsigned long cvaddr;

	/* Current offset in pages file */
	off_t pi_off;
	/* Alignment bytes a sequential image-streamer reader must discard. */
	size_t stream_padding;

	/*
	 * Index into pe->compressed_size[] for the current pagemap
	 * entry. Tracks which compressed block (page in per-page mode,
	 * region in region mode) we are on when reading or skipping
	 * compressed pages. Reset to 0 on advance().
	 */
	size_t compressed_size_index;

	/*
	 * In region mode: pages already consumed (read or skipped) from
	 * the current block. Always 0 in per-page mode. Reset to 0 on
	 * advance() and whenever the reader crosses a block boundary.
	 */
	unsigned int region_block_offset;

	/*
	 * Last decompressed region block for repeated partial reads. A page
	 * reader belongs to one pages image, so its virtual address and size
	 * uniquely identify the cached block. A zero size means no valid cache.
	 */
	char *cached_region;
	unsigned long cached_region_vaddr;
	size_t cached_region_size;

	/*
	 * Bounded encoded buffers and workers. All readers in an incremental
	 * parent chain use the context owned by encoded_read_owner, so a sync
	 * initiated by a parent cannot acquire a second batch lease and deadlock
	 * against its child. Only the owner releases the context at close.
	 */
	struct encoded_read_ctx *encoded_read_ctx;
	struct page_read *encoded_read_owner;

	/* Record consequent neighbour iov-ecs to punch together */
	struct iovec bunch;

	/* For logging */
	unsigned id;

	/* Pagemap image file ID */
	unsigned long img_id;

	PagemapEntry **pmes;
	int nr_pmes;
	int curr_pme;

	struct list_head async;
};

/* flags for ->read_pages */
#define PR_ASYNC 0x1 /* may exit w/o data in the buffer */
#define PR_ASAP	 0x2 /* PR_ASYNC, but start the IO right now */

/* flags for open_page_read */
#define PR_SHMEM 0x1
#define PR_TASK	 0x2

#define PR_TYPE_MASK 0x3
#define PR_MOD	     0x4 /* Will need to modify */
#define PR_REMOTE    0x8

/*
 * -1 -- error
 *  0 -- no images
 *  1 -- opened
 */
extern int open_page_read(unsigned long id, struct page_read *, int pr_flags);
extern int open_page_read_at(int dfd, unsigned long id, struct page_read *pr, int pr_flags);

struct task_restore_args;

int pagemap_enqueue_iovec(struct page_read *pr, void *buf, unsigned long len, struct list_head *to);
int pagemap_render_iovec(struct list_head *from, struct task_restore_args *ta);

/*
 * Return true when every file-backed queued read can be submitted with
 * O_DIRECT. Encoded storage is rejected; raw storage and all destination
 * extents must be page-aligned. Zero entries have no file extent, and a
 * zero-only list returns false because it needs no AIO setup.
 */
bool pagemap_iovec_is_direct_compatible(const struct list_head *from);

/*
 * Return whether any page-image block overlapping [start, end) contains an
 * actual LZ4 payload. Raw-fallback and zero blocks return false. Parent-image
 * entries are followed without changing either reader's cursor.
 *
 * A local lookup is O(log(nr_pmes) + overlapping entries/blocks). Each
 * inherited span repeats that lookup in the parent, so a fragmented parent
 * chain additionally pays one logarithmic lookup per inherited span. A
 * negative return indicates invalid input or an inconsistent parent chain.
 */
int page_read_range_has_lz4(struct page_read *pr, unsigned long start,
			     unsigned long end);

/* Also return true when raw/zero runs exceed the bounded direct-PIE limit. */
int page_read_range_needs_premap(struct page_read *pr, unsigned long start,
				  unsigned long end);

/* Return whether the top image delegates any part of [start, end) to a parent. */
int page_read_range_has_parent(struct page_read *pr, unsigned long start,
				unsigned long end);

/*
 * Try to enable O_DIRECT on a pages-image fd and verify with one
 * aligned probe read.
 *
 *   1 - O_DIRECT enabled
 *   0 - O_DIRECT disabled or rejected; fd left in usable buffered
 *       state with POSIX_FADV_SEQUENTIAL hinted
 *  -1 - hard error; caller releases the fd
 *
 * PAGE_SIZE is not a compile-time constant on aarch64, so the probe
 * buffer comes from posix_memalign().
 */
int probe_pages_o_direct(int fd);

/*
 * Create a shallow copy of page_read object.
 * The new object shares the pagemap structures with the original, but
 * maintains its own set of references to those structures.
 */
extern void dup_page_read(struct page_read *src, struct page_read *dst);
extern void page_read_free_cache(struct page_read *pr);

extern void page_read_disable_dedup(struct page_read *pr);

extern int dedup_one_iovec(struct page_read *pr, unsigned long base, unsigned long len);

static inline unsigned long pagemap_len(PagemapEntry *pe)
{
	return pe->nr_pages * PAGE_SIZE;
}

static inline bool page_read_has_parent(struct page_read *pr)
{
	return pr->parent != NULL;
}

/* Pagemap flags */
#define PE_PARENT  (1 << 0) /* pages are in parent snapshot */
#define PE_LAZY	   (1 << 1) /* pages can be lazily restored */
#define PE_PRESENT (1 << 2) /* pages are present in pages*img */
#define PE_PAYLOAD_ALIGNED (1 << 3) /* payload starts at a page boundary */

static inline bool pagemap_in_parent(PagemapEntry *pe)
{
	return !!(pe->flags & PE_PARENT);
}

static inline bool pagemap_lazy(PagemapEntry *pe)
{
	return !!(pe->flags & PE_LAZY);
}

static inline bool pagemap_present(PagemapEntry *pe)
{
	return !!(pe->flags & PE_PRESENT);
}

static inline bool pagemap_payload_aligned(PagemapEntry *pe)
{
	return !!(pe->flags & PE_PAYLOAD_ALIGNED);
}

/* Keep the mask as wide as off_t so offsets above 4 GiB remain intact. */
static inline off_t pagemap_page_align_offset(off_t offset)
{
	off_t mask = ~((off_t)PAGE_SIZE - 1);

	return (offset + (off_t)PAGE_SIZE - 1) & mask;
}

#endif /* __CR_PAGE_READ_H__ */
