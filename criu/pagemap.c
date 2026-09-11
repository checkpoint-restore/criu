#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <linux/falloc.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <limits.h>

#include "types.h"
#include "atomic.h"
#include "image.h"
#include "cr_options.h"
#include "servicefd.h"
#include "pagemap.h"
#include "restorer.h"
#include "rst-malloc.h"
#include "page-xfer.h"
#include "pagemap-block.h"
#include "compression.h"
#include "namespaces.h"

#include "fault-injection.h"
#include "xmalloc.h"
#include "protobuf.h"
#include "images/pagemap.pb-c.h"

#ifndef SEEK_DATA
#define SEEK_DATA 3
#define SEEK_HOLE 4
#endif

#define MAX_BUNCH_SIZE 256
#define PAGE_PADDING_CHUNK 4096
#define ASYNC_READAHEAD_MAX_GAP (1UL << 20)
#define ASYNC_READAHEAD_MAX_BYTES (256UL << 20)
#define DIRECT_COMPRESSED_RUN_MAX 128
/*
 * Splitting a tiny raw/zero island out of an encoded batch trades a memcpy for
 * another restore job (and, for raw data, another preadv()).  Keep small
 * islands with neighbouring LZ4 blocks, while always exposing raw/zero ranges
 * when the whole request can be restored without LZ4.
 */
#define DIRECT_COMPRESSED_RUN_MIN_BYTES (64UL * 1024)

#define OFF_MAX (sizeof(off_t) == sizeof(long long) ? LLONG_MAX : sizeof(off_t) == sizeof(int) ? INT_MAX : -999999)
#define OFF_MIN (sizeof(off_t) == sizeof(long long) ? LLONG_MIN : sizeof(off_t) == sizeof(int) ? INT_MIN : -999999)

static inline bool can_extend_bunch(struct iovec *bunch, unsigned long off, unsigned long len)
{
	return /* The next region is the continuation of the existing */
		((unsigned long)bunch->iov_base + bunch->iov_len == off) &&
		/* The resulting region is non empty and is small enough */
		(bunch->iov_len == 0 || bunch->iov_len + len < MAX_BUNCH_SIZE * PAGE_SIZE);
}

static int punch_hole(struct page_read *pr, unsigned long off, unsigned long len, bool cleanup)
{
	int ret;
	struct iovec *bunch = &pr->bunch;

	if (!cleanup && can_extend_bunch(bunch, off, len)) {
		pr_debug("pr%lu-%u:Extend bunch len from %zu to %lu\n", pr->img_id, pr->id, bunch->iov_len,
			 bunch->iov_len + len);
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
		struct page_read *prp;

		ret = pr->seek_pagemap(pr, off);
		if (ret == 0) {
			if (off < pr->cvaddr && pr->cvaddr < iov_end) {
				pr_debug("pr%lu-%u:No range %lx-%lx in pagemap\n", pr->img_id, pr->id, off, pr->cvaddr);
				off = pr->cvaddr;
			} else {
				pr_debug("pr%lu-%u:No range %lx-%lx in pagemap\n", pr->img_id, pr->id, off, iov_end);
				return 0;
			}
		}

		if (!pr->pe)
			return -1;
		piov_end = pr->pe->vaddr + pagemap_len(pr->pe);
		if (!pagemap_in_parent(pr->pe)) {
			/*
			 * Skip hole-punching for compressed entries.
			 * fallocate(PUNCH_HOLE) zeroes whole filesystem
			 * blocks (typically 4K). Compressed pages are
			 * smaller than a block and packed contiguously,
			 * so punching one would destroy adjacent pages
			 * that share the same block.
			 */
			if (!pr->pe->blocks) {
				unsigned long punch_len = min(piov_end, iov_end) - off;

				ret = punch_hole(pr, pr->pi_off, punch_len, false);
				if (ret == -1)
					return ret;
			}
		}

		prp = pr->parent;
		if (prp) {
			/* recursively */
			pr_debug("pr%lu-%u:Go to next parent level\n", pr->img_id, pr->id);
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

void page_read_free_cache(struct page_read *pr)
{
	xfree(pr->blk.cache_buf);
	pr->blk.cache_buf = NULL;
	pr->blk.cache_vaddr = 0;
	pr->blk.cache_size = 0;
}

static int advance(struct page_read *pr)
{
	pr->curr_pme++;
	if (pr->curr_pme >= pr->nr_pmes)
		return 0;

	pr->pe = pr->pmes[pr->curr_pme];
	pr->cvaddr = pr->pe->vaddr;
	pr->stream_padding = 0;
	if (pagemap_present(pr->pe) && pagemap_payload_aligned(pr->pe)) {
		off_t aligned;

		/* init_pagemaps() rejects this; retain a checked guard here so
		 * malformed state can never trigger signed off_t overflow. */
		if (pr->pi_off < 0 || pr->pi_off > OFF_MAX - (PAGE_SIZE - 1)) {
			pr_err("Pages image offset %jd cannot be page-aligned\n",
			       (intmax_t)pr->pi_off);
			return 0;
		}
		aligned = pagemap_page_align_offset(pr->pi_off);

		pr->stream_padding = aligned - pr->pi_off;
		pr->pi_off = aligned;
	}

	pr->blk.block_idx = 0;
	pr->blk.block_offset = 0;

	return 1;
}

/*
 * Return the page count of the current compressed block.
 * The last block of an entry may be shorter than pages_per_block when the
 * entry's nr_pages is not a multiple of pages_per_block.
 */
static unsigned int current_block_pages(struct page_read *pr)
{
	unsigned int block_pages = pagemap_block_pages(pr->pe);
	uint64_t pages_before = (uint64_t)pr->blk.block_idx * block_pages;
	uint64_t pages_left = pr->pe->nr_pages - pages_before;

	return pages_left < block_pages ? (unsigned int)pages_left : block_pages;
}

/*
 * Advance the file offset (pi_off) by @len bytes without reading
 * the page data. Used by seek_pagemap() to skip over pages that
 * are not needed for the current read request.
 */
static void skip_pagemap_pages(struct page_read *pr, unsigned long len)
{
	if (!len)
		return;

	if (pagemap_present(pr->pe)) {
		if (!pr->pe->blocks || !pr->pe->blocks->n_block_sizes) {
			pr->pi_off += len;
		} else if (pr->blk.block_idx == 0 &&
			   pr->blk.block_offset == 0 &&
			   (uint64_t)(len / PAGE_SIZE) == pr->pe->nr_pages) {
			/*
			 * Fast path: skipping a whole compressed entry from
			 * its start. total_payload_size equals the sum of
			 * block_sizes[], so advance pi_off by it in a single
			 * step instead of walking every block. Mark all blocks
			 * consumed so the reader state matches below.
			 */
			pr->pi_off += pr->pe->blocks->total_payload_size;
			pr->blk.block_idx = pr->pe->blocks->n_block_sizes;
		} else {
			/*
			 * Block mode: each block_sizes[] entry covers up to
			 * pages_per_block pages. Walk forward, advancing the
			 * in-block cursor and crossing block boundaries by
			 * adding the block's size to pi_off.
			 */
			unsigned long nr = len / PAGE_SIZE;

			while (nr > 0) {
				unsigned int bp = current_block_pages(pr);
				unsigned int avail = bp - pr->blk.block_offset;
				unsigned int take = avail;

				if (nr < avail)
					take = (unsigned int)nr;

				if (pr->blk.block_idx >= pr->pe->blocks->n_block_sizes) {
					pr_err("skip_pagemap_pages: index out of bounds: "
					       "%zu >= %zu\n",
					       pr->blk.block_idx,
					       pr->pe->blocks->n_block_sizes);
					BUG();
				}

				pr->blk.block_offset += take;
				nr -= take;

				if (pr->blk.block_offset == bp) {
					pr->pi_off += pr->pe->blocks->block_sizes[pr->blk.block_idx];
					pr->blk.block_idx++;
					pr->blk.block_offset = 0;
				}
			}
		}
	}
	pr->cvaddr += len;
}

static int seek_pagemap(struct page_read *pr, unsigned long vaddr)
{
	if (!pr->pe)
		goto adv;

	do {
		unsigned long start = pr->pe->vaddr;
		unsigned long end = start + pagemap_len(pr->pe);

		if (vaddr < pr->cvaddr)
			break;

		if (vaddr >= start && vaddr < end) {
			skip_pagemap_pages(pr, vaddr - pr->cvaddr);
			return 1;
		}

		if (end <= vaddr)
			skip_pagemap_pages(pr, end - pr->cvaddr);
	adv:; /* otherwise "label at end of compound stmt" gcc error */
	} while (advance(pr));

	return 0;
}

static inline void pagemap_bound_check(PagemapEntry *pe, unsigned long vaddr, unsigned long int nr)
{
	if (vaddr < pe->vaddr || (vaddr - pe->vaddr) / PAGE_SIZE + nr > pe->nr_pages) {
		pr_err("Page read err %" PRIx64 ":%" PRIx64 " vs %lx:%lx\n", pe->vaddr, pe->nr_pages, vaddr, nr);
		BUG();
	}
}

static int read_parent_page(struct page_read *pr, unsigned long vaddr, unsigned long int nr, void *buf, unsigned flags)
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
		unsigned long int p_nr;

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
		pr_info("\tparent has %lu pages in\n", p_nr);
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

static int read_local_page(struct page_read *pr, unsigned long vaddr, unsigned long len, void *buf)
{
	int fd;
	ssize_t ret;
	size_t curr = 0;

	fd = img_raw_fd(pr->pi);
	if (fd < 0) {
		pr_err("Failed getting raw image fd\n");
		return -1;
	}
	/*
	 * Flush any pending async requests if any not to break the
	 * linear reading from the pages.img file.
	 */
	if (pr->sync(pr))
		return -1;

	pr_debug("\tpr%lu-%u Read page from self %lx/%" PRIx64 "\n", pr->img_id, pr->id, pr->cvaddr, pr->pi_off);
	while (1) {
		ret = pread(fd, buf + curr, len - curr, pr->pi_off + curr);
		if (ret < 1) {
			pr_perror("Can't read mapping page %zd", ret);
			return -1;
		}
		curr += ret;
		if (curr == len)
			break;
	}

	if (opts.auto_dedup && !pr->disable_dedup) {
		ret = punch_hole(pr, pr->pi_off, len, false);
		if (ret == -1)
			return -1;
	}

	return 0;
}

static int compressed_block_layout(const PagemapEntry *pe, size_t index,
				   unsigned int *block_pages, size_t *block_bytes)
{
	unsigned int pages_per_block = pagemap_block_pages(pe);
	uint64_t first_page;
	uint64_t pages_left;

	if (!pe || !pe->blocks || index >= pe->blocks->n_block_sizes) {
		pr_err("Compressed block index %zu is out of bounds\n", index);
		return -1;
	}

	first_page = (uint64_t)index * pages_per_block;
	if (first_page >= pe->nr_pages) {
		pr_err("Compressed block %zu starts past entry end (%" PRIu64 " pages)\n",
		       index, pe->nr_pages);
		return -1;
	}
	pages_left = pe->nr_pages - first_page;
	*block_pages = pages_left < pages_per_block ?
				(unsigned int)pages_left : pages_per_block;
	*block_bytes = (size_t)*block_pages * PAGE_SIZE;
	return 0;
}

static int compressed_block_storage(const PagemapEntry *pe, size_t index,
				    enum restore_vma_io_storage *storage,
				    unsigned int *block_pages)
{
	size_t block_bytes;
	uint32_t compressed_size;

	if (compressed_block_layout(pe, index, block_pages, &block_bytes))
		return -1;

	compressed_size = pe->blocks->block_sizes[index];
	if (!compressed_size)
		*storage = VMA_IO_ZERO;
	else if (compressed_size == block_bytes)
		*storage = VMA_IO_PACKED_RAW;
	else
		*storage = VMA_IO_ENCODED;
	return 0;
}

static int piov_add_compressed_blocks(struct page_read_iov *piov,
				      struct page_read *pr,
				      unsigned long nr_pages,
				      enum restore_vma_io_storage storage)
{
	unsigned int block_pages = pagemap_block_pages(pr->pe);
	size_t first = piov->b_layout.nr_blocks;
	unsigned long n_blocks;
	uint16_t *new_bp = NULL;
	uint32_t *new_cs;
	uint64_t added = 0;
	size_t new_n;
	unsigned long i;
	uint64_t pages_consumed = (uint64_t)pr->blk.block_idx * block_pages;
	uint64_t end_page = pages_consumed + nr_pages;

	/*
	 * Block mode allows two alignment cases: nr_pages is
	 * a multiple of pages_per_block, or the read finishes
	 * exactly at the entry's end (last block may be
	 * shorter than pages_per_block).
	 */
	if (pages_consumed % block_pages != 0 ||
	    (nr_pages % block_pages != 0 &&
	     end_page != pr->pe->nr_pages)) {
		if (first)
			pr_err("Block-mode async append not aligned: idx=%zu nr=%lu block=%u nr_pages=%" PRIu64 "\n",
			       pr->blk.block_idx, nr_pages,
			       block_pages, pr->pe->nr_pages);
		else
			pr_err("Block-mode async enqueue not aligned: idx=%zu nr=%lu block=%u nr_pages=%" PRIu64 "\n",
			       pr->blk.block_idx, nr_pages,
			       block_pages, pr->pe->nr_pages);
		return -1;
	}
	n_blocks = block_nr_blocks(nr_pages, block_pages);

	if (!pr->pe->blocks || pr->blk.block_idx + n_blocks >
	    pr->pe->blocks->n_block_sizes) {
		pr_err("Compressed size index out of bounds: %zu + %lu > %zu\n",
		       pr->blk.block_idx, n_blocks,
		       pr->pe->blocks ? pr->pe->blocks->n_block_sizes : 0);
		return -1;
	}

	new_n = first + n_blocks;
	new_cs = xrealloc(piov->b_layout.sizes, new_n * sizeof(*piov->b_layout.sizes));
	if (!new_cs)
		return -1;
	piov->b_layout.sizes = new_cs;

	new_bp = xrealloc(piov->block_pages, new_n * sizeof(*piov->block_pages));
	if (!new_bp)
		return -1;
	piov->block_pages = new_bp;

	for (i = 0; i < n_blocks; i++) {
		size_t idx = pr->blk.block_idx + i;
		enum restore_vma_io_storage block_storage;
		unsigned int cur_block_pages;
		uint32_t cs = pr->pe->blocks->block_sizes[idx];

		if (compressed_block_storage(pr->pe, idx, &block_storage,
					     &cur_block_pages))
			return -1;
		if ((storage == VMA_IO_PACKED_RAW || storage == VMA_IO_ZERO) &&
		    block_storage != storage) {
			pr_err("Block %zu has storage kind %d, expected %d\n",
			       idx, block_storage, storage);
			return -1;
		}

		piov->b_layout.sizes[first + i] = cs;
		piov->block_pages[first + i] = (uint16_t)cur_block_pages;
		added += cs;
	}

	piov->b_layout.total_bytes += added;
	piov->b_layout.nr_blocks = new_n;
	piov->b_layout.pages_per_block = block_pages;
	piov->end += added;

	return 0;
}

static int enqueue_async_iov(struct page_read *pr, void *buf, unsigned long len,
			     struct list_head *to,
			     enum restore_vma_io_storage storage)
{
	struct page_read_iov *pr_iov;
	struct iovec *iov;

	if (!len || len % PAGE_SIZE) {
		pr_err("Invalid async page-read length %lu\n", len);
		return -1;
	}
	if (storage == VMA_IO_UNCOMPRESSED && pr->pe &&
	    pr->pe->blocks) {
		pr_err("Uncompressed async job has compression metadata\n");
		return -1;
	}
	if (storage != VMA_IO_UNCOMPRESSED &&
	    (!pr->pe || !pr->pe->blocks)) {
		pr_err("Packed async job has no compression metadata\n");
		return -1;
	}

	pr_iov = xzalloc(sizeof(*pr_iov));
	if (!pr_iov)
		return -1;

	pr_iov->from = pr->pi_off;
	pr_iov->end = pr_iov->from;

	iov = xzalloc(sizeof(*iov));
	if (!iov) {
		xfree(pr_iov);
		return -1;
	}

	iov->iov_base = buf;
	iov->iov_len = len;

	pr_iov->to = iov;
	pr_iov->nr = 1;
	pr_iov->n_pages = len / PAGE_SIZE;
	pr_iov->storage = storage;

	/*
	 * For uncompressed entries, the end offset is simply
	 * start + len. For compressed entries, copy the per-block
	 * sizes so that process_async_reads() knows how much
	 * compressed data to read from the image.
	 */
	if (storage == VMA_IO_UNCOMPRESSED)
		pr_iov->end += len;
	else if (piov_add_compressed_blocks(pr_iov, pr, len / PAGE_SIZE, storage))
		goto err;

	list_add_tail(&pr_iov->l, to);

	return 0;

err:
	xfree(pr_iov->block_pages);
	xfree(pr_iov->b_layout.sizes);
	xfree(iov);
	xfree(pr_iov);
	return -1;
}

int pagemap_render_iovec(struct list_head *from, struct task_restore_args *ta)
{
	struct page_read_iov *piov;

	/*
	 * Pass 1: copy each entry's compressed metadata (sizes[] and
	 * block_pages[]) into restorer memory and remember their RM_PRIVATE
	 * offsets.
	 *
	 * These must be allocated before the contiguous rio array (pass 2)
	 * for two reasons: the restorer strides over the rio array with
	 * RIO_SIZE(), so nothing may be interleaved between rios; and
	 * rst_mem_alloc() can move the arena, so a rio pointer must never be
	 * held across a subsequent allocation. Offsets are stored (not
	 * pointers) because struct restore_vma_io references them through
	 * RST_MEM_FIXUP_PPTR, which adds the remapped base to the value.
	 */
	list_for_each_entry(piov, from, l) {
		size_t sz;
		void *p;

		piov->rio_cs_off = 0;
		piov->rio_bp_off = 0;

		if (!piov->b_layout.nr_blocks)
			continue;

		sz = piov->b_layout.nr_blocks * sizeof(uint32_t);
		piov->rio_cs_off = rst_mem_align_cpos(RM_PRIVATE);
		p = rst_mem_alloc(sz, RM_PRIVATE);
		if (!p)
			return -1;
		memcpy(p, piov->b_layout.sizes, sz);

		if (piov->b_layout.pages_per_block) {
			sz = piov->b_layout.nr_blocks * sizeof(uint16_t);
			piov->rio_bp_off = rst_mem_align_cpos(RM_PRIVATE);
			p = rst_mem_alloc(sz, RM_PRIVATE);
			if (!p)
				return -1;
			memcpy(p, piov->block_pages, sz);
		}
	}

	/* Pass 2: build the contiguous rio array. */
	ta->vma_ios = (struct restore_vma_io *)rst_mem_align_cpos(RM_PRIVATE);
	ta->vma_ios_n = 0;

	list_for_each_entry(piov, from, l) {
		struct restore_vma_io *rio;

		pr_info("`- render %d iovs (%p:%zd...)\n", piov->nr, piov->to[0].iov_base, piov->to[0].iov_len);
		rio = rst_mem_alloc(RIO_SIZE(piov->nr), RM_PRIVATE);
		if (!rio)
			return -1;

		rio->nr_iovs = piov->nr;
		rio->off = piov->from;
		rio->storage = piov->storage;

		/* Ordinary reads do not carry compressed block metadata. */
		if (!piov->b_layout.nr_blocks) {
			rio->b_layout.sizes = NULL;
			rio->b_layout.nr_blocks = 0;
			rio->b_layout.total_bytes = 0;
			rio->b_layout.pages_per_block = 0;
			rio->n_pages = 0;
			rio->block_pages = NULL;
		} else {
			/* Use the block metadata copied in pass 1. */
			rio->b_layout.sizes = (uint32_t *)piov->rio_cs_off;
			rio->b_layout.nr_blocks = piov->b_layout.nr_blocks;
			rio->b_layout.total_bytes = piov->b_layout.total_bytes;
			rio->b_layout.pages_per_block = piov->b_layout.pages_per_block;

			/* The final block may contain fewer pages. */
			if (piov->b_layout.pages_per_block) {
				uint64_t pages_total = 0;
				size_t i;

				rio->block_pages = (uint16_t *)piov->rio_bp_off;
				for (i = 0; i < piov->b_layout.nr_blocks; i++)
					pages_total += piov->block_pages[i];

				if (pages_total > INT_MAX) {
					pr_err("restore_vma_io exceeds int page count limit: %llu\n",
					       (unsigned long long)pages_total);
					return -1;
				}
				rio->n_pages = (int)pages_total;
			} else {
				rio->block_pages = NULL;

				if (piov->b_layout.nr_blocks > (size_t)INT_MAX) {
					pr_err("restore_vma_io exceeds int page count limit: %zu\n",
					       piov->b_layout.nr_blocks);
					return -1;
				}
				rio->n_pages = piov->b_layout.nr_blocks;
			}
		}

		memcpy(rio->iovs, piov->to, piov->nr * sizeof(struct iovec));

		ta->vma_ios_n++;
	}

	return 0;
}

static int advance_compressed_offsets(struct page_read *pr, unsigned long nr)
{
	unsigned int block_pages = pagemap_block_pages(pr->pe);
	unsigned long n_blocks, i;

	/*
	 * Whole-entry skip from its start: advance by total_payload_size
	 * in one step instead of summing every block. The caller guarantees
	 * block_offset is 0 here, so block_idx == 0 means
	 * we are at the start.
	 */
	if (pr->blk.block_idx == 0 && pr->pe->blocks &&
	    (uint64_t)nr == pr->pe->nr_pages) {
		pr->pi_off += pr->pe->blocks->total_payload_size;
		pr->blk.block_idx = pr->pe->blocks->n_block_sizes;
		return 0;
	}

	n_blocks = block_nr_blocks(nr, block_pages);

	if (!pr->pe->blocks || pr->blk.block_idx + n_blocks > pr->pe->blocks->n_block_sizes) {
		pr_err("advance_compressed_offsets: index out of bounds: %zu + %lu > %zu\n",
		       pr->blk.block_idx, n_blocks, pr->pe->blocks ? pr->pe->blocks->n_block_sizes : 0);
		return -1;
	}

	for (i = 0; i < n_blocks; i++)
		pr->pi_off += pr->pe->blocks->block_sizes[pr->blk.block_idx + i];
	pr->blk.block_idx += n_blocks;

	return 0;
}

static int compressed_request_has_lz4(struct page_read *pr,
				       unsigned long nr_pages, bool *has_lz4,
				       bool *mixed_direct)
{
	size_t index = pr->blk.block_idx;
	enum restore_vma_io_storage previous_storage = VMA_IO_UNCOMPRESSED;
	bool have_previous_storage = false;
	unsigned long pages_done = 0;

	*has_lz4 = false;
	*mixed_direct = false;
	while (pages_done < nr_pages) {
		enum restore_vma_io_storage storage;
		unsigned int block_pages;

		if (compressed_block_storage(pr->pe, index, &storage,
					     &block_pages))
			return -1;
		if (block_pages > nr_pages - pages_done) {
			pr_err("Compressed request ends inside block %zu\n", index);
			return -1;
		}
		if (storage == VMA_IO_ENCODED)
			*has_lz4 = true;
		else if (have_previous_storage && storage != previous_storage)
			*mixed_direct = true;
		if (storage != VMA_IO_ENCODED) {
			previous_storage = storage;
			have_previous_storage = true;
		}
		pages_done += block_pages;
		index++;
	}

	return 0;
}

static int compressed_storage_run(struct page_read *pr,
				  unsigned long pages_left,
				  enum restore_vma_io_storage *storage,
				  unsigned long *run_pages,
				  size_t *run_blocks)
{
	size_t index = pr->blk.block_idx;
	enum restore_vma_io_storage first_storage;
	unsigned int block_pages;

	if (compressed_block_storage(pr->pe, index, &first_storage,
				     &block_pages))
		return -1;

	*run_pages = 0;
	*run_blocks = 0;
	while (*run_pages < pages_left) {
		enum restore_vma_io_storage block_storage = first_storage;

		if (*run_pages) {
			if (compressed_block_storage(pr->pe, index, &block_storage, &block_pages))
				return -1;
		}
		if (block_storage != first_storage)
			break;
		if (block_pages > pages_left - *run_pages) {
			pr_err("Compressed request ends inside block %zu\n", index);
			return -1;
		}
		if (*run_pages &&
		    block_pages > ASYNC_BATCH_MAX_PAGES - *run_pages)
			break;
		*run_pages += block_pages;
		(*run_blocks)++;
		index++;
		if (*run_pages >= ASYNC_BATCH_MAX_PAGES)
			break;
	}

	if (!*run_pages) {
		pr_err("Unable to form compressed storage run at block %zu\n",
		       pr->blk.block_idx);
		return -1;
	}
	*storage = first_storage;
	return 0;
}

static int pagemap_enqueue_iovec_one(struct page_read *pr, void *buf,
				     unsigned long len, struct list_head *to,
				     enum restore_vma_io_storage storage)
{
	struct page_read_iov *cur_async = NULL;
	struct iovec *iov;
	bool extended_iov = false;
	bool added_iov = false;
	unsigned int new_block_pages = 0;

	if (storage != VMA_IO_UNCOMPRESSED)
		new_block_pages = pagemap_block_pages(pr->pe);

	if (!list_empty(to))
		cur_async = list_entry(to->prev, struct page_read_iov, l);

	/*
	 * We don't have any async requests or we have new read
	 * request that should happen at pos _after_ some hole from
	 * the previous one.
	 * Start the new preadv request here.
	 */
	if (!cur_async || pr->pi_off != cur_async->end)
		return enqueue_async_iov(pr, buf, len, to, storage);

	/* Different storage kinds have different restore and dedup rules. */
	if (cur_async->storage != storage)
		return enqueue_async_iov(pr, buf, len, to, storage);

	/*
	 * Don't merge piovs with different block sizes: each piov is
	 * decompressed with a single block layout.
	 */
	if (cur_async->b_layout.pages_per_block != new_block_pages)
		return enqueue_async_iov(pr, buf, len, to, storage);

	/*
	 * Cap a compressed async batch by its UNCOMPRESSED page count.
	 * process_async_reads() reads an encoded batch into one buffer and
	 * allocates per-block job metadata, while delayed raw/zero batches copy
	 * their block metadata into restorer memory. Bounding pages bounds both
	 * working sets. A compressed-byte cap alone would not bound metadata for
	 * highly compressible or zero-filled data, whose payload can be tiny or
	 * empty while the logical range grows to many GiB.
	 * The check is gated on compression; uncompressed async reads go
	 * straight into their destination iovecs and need no cap.
	 */
	if (storage != VMA_IO_UNCOMPRESSED &&
	    cur_async->n_pages + len / PAGE_SIZE > ASYNC_BATCH_MAX_PAGES)
		return enqueue_async_iov(pr, buf, len, to, storage);

	/*
	 * This read is pure continuation of the previous one. Let's
	 * just add another IOV (or extend one of the existing).
	 */
	iov = &cur_async->to[cur_async->nr - 1];
	if (iov->iov_base + iov->iov_len == buf) {
		/* Extendable */
		iov->iov_len += len;
		extended_iov = true;
	} else {
		/* Need one more target iovec */
		unsigned int n_iovs = cur_async->nr + 1;

		if (n_iovs > IOV_MAX)
			return enqueue_async_iov(pr, buf, len, to, storage);

		iov = xrealloc(cur_async->to, n_iovs * sizeof(*iov));
		if (!iov)
			return -1;

		cur_async->to = iov;

		iov += cur_async->nr;
		iov->iov_base = buf;
		iov->iov_len = len;

		cur_async->nr = n_iovs;
		added_iov = true;
	}

	/*
	 * Count the pages only once the read is actually appended to this
	 * batch -- after the IOV_MAX spill (which redirects to a fresh
	 * piov) so the cap input is not inflated by pages that landed
	 * elsewhere.
	 */
	cur_async->n_pages += len / PAGE_SIZE;

	/* Extend the end offset. For compressed entries, append
	 * per-block sizes and advance by compressed bytes. */
	if (storage == VMA_IO_UNCOMPRESSED) {
		cur_async->end += len;
	} else if (piov_add_compressed_blocks(cur_async, pr, len / PAGE_SIZE, storage))
		goto rollback_iov;

	return 0;

rollback_iov:
	cur_async->n_pages -= len / PAGE_SIZE;
	if (extended_iov)
		cur_async->to[cur_async->nr - 1].iov_len -= len;
	else if (added_iov)
		cur_async->nr--;
	return -1;
}

int pagemap_enqueue_iovec(struct page_read *pr, void *buf, unsigned long len, struct list_head *to)
{
	struct page_read_iov *original_tail = NULL;
	off_t original_end = 0;
	size_t original_nr_blocks = 0;
	uint64_t original_total_compressed_size = 0;
	unsigned long original_n_pages = 0;
	unsigned int original_nr = 0;
	size_t original_last_iov_len = 0;
	unsigned long nr_pages = len / PAGE_SIZE;
	bool has_lz4;
	bool mixed_direct;
	bool parallel_zero = false;
	off_t pi_off;
	size_t saved_block_idx;
	unsigned int saved_block_offset;
	unsigned long done = 0;
	int ret = 0;

	if (!len || len % PAGE_SIZE) {
		pr_err("Invalid pagemap I/O length %lu\n", len);
		return -1;
	}

	if (!pr->pe || !pr->pe->blocks)
		return pagemap_enqueue_iovec_one(pr, buf, len, to,
						VMA_IO_UNCOMPRESSED);

	if (compressed_request_has_lz4(pr, nr_pages, &has_lz4,
					&mixed_direct))
		return -1;
	if (to == &pr->async)
		parallel_zero = compressed_restore_has_parallel_capacity(opts.decompress_threads);

	pi_off = pr->pi_off;
	saved_block_idx = pr->blk.block_idx;
	saved_block_offset = pr->blk.block_offset;
	if (!list_empty(to)) {
		original_tail = list_entry(to->prev, struct page_read_iov, l);
		original_end = original_tail->end;
		original_nr_blocks = original_tail->b_layout.nr_blocks;
		original_total_compressed_size =
			original_tail->b_layout.total_bytes;
		original_n_pages = original_tail->n_pages;
		original_nr = original_tail->nr;
		original_last_iov_len = original_tail->to[original_nr - 1].iov_len;
	}

	while (done < nr_pages) {
		enum restore_vma_io_storage storage;
		unsigned long chunk;
		size_t blocks;

		if (compressed_storage_run(pr, nr_pages - done, &storage,
					   &chunk, &blocks)) {
			ret = -1;
			break;
		}

		/* Premapped large zero runs can share the decompression worker pool. */
		if (storage == VMA_IO_ZERO && parallel_zero && blocks > 1 &&
		    chunk * PAGE_SIZE >= PARALLEL_RESTORE_MIN_BATCH_BYTES)
			storage = VMA_IO_ENCODED;

		/*
		 * Keep short raw/zero islands in an in-process encoded batch when
		 * the request either contains LZ4 or was premapped because it has
		 * too many direct runs. Adjacent short runs then coalesce, while
		 * long raw/zero runs retain their direct paths. PIE requests remain
		 * split because PIE cannot decode an encoded batch.
		 */
		if (storage != VMA_IO_ENCODED &&
		    (has_lz4 || (mixed_direct && to == &pr->async)) &&
		    chunk * PAGE_SIZE < DIRECT_COMPRESSED_RUN_MIN_BYTES)
			storage = VMA_IO_ENCODED;

		ret = pagemap_enqueue_iovec_one(pr, (char *)buf + done * PAGE_SIZE,
						chunk * PAGE_SIZE, to, storage);
		if (ret)
			break;

		ret = advance_compressed_offsets(pr, chunk);
		if (ret)
			break;

		done += chunk;
	}

	pr->pi_off = pi_off;
	pr->blk.block_idx = saved_block_idx;
	pr->blk.block_offset = saved_block_offset;
	if (ret) {
		/*
		 * One logical request may be split into multiple storage runs. If
		 * a later allocation or metadata check fails, remove every new
		 * piov and restore a pre-existing tail that earlier runs extended.
		 * Leaving a prefix queued would make the caller's error cleanup hit
		 * close_page_read() with an unexpected non-empty async list.
		 */
		while (!list_empty(to) &&
		       (!original_tail || to->prev != &original_tail->l)) {
			struct page_read_iov *piov =
				list_entry(to->prev, struct page_read_iov, l);

			list_del(&piov->l);
			xfree(piov->b_layout.sizes);
			xfree(piov->block_pages);
			xfree(piov->to);
			xfree(piov);
		}
		if (original_tail) {
			original_tail->end = original_end;
			original_tail->b_layout.nr_blocks =
				original_nr_blocks;
			original_tail->b_layout.total_bytes =
				original_total_compressed_size;
			original_tail->n_pages = original_n_pages;
			original_tail->nr = original_nr;
			original_tail->to[original_nr - 1].iov_len =
				original_last_iov_len;
		}
	}

	return ret;
}

bool pagemap_iovec_is_direct_compatible(const struct list_head *from)
{
	const struct page_read_iov *piov;
	bool has_file_backed = false;

	list_for_each_entry(piov, from, l) {
		uint64_t destination_bytes = 0;
		unsigned int i;

		if (!piov->nr || piov->storage == VMA_IO_ENCODED)
			return false;
		if (piov->storage != VMA_IO_UNCOMPRESSED &&
		    piov->storage != VMA_IO_PACKED_RAW &&
		    piov->storage != VMA_IO_ZERO)
			return false;
		if (piov->storage != VMA_IO_ZERO &&
		    (piov->from < 0 || piov->end < piov->from ||
		     piov->from % (off_t)PAGE_SIZE ||
		     (piov->end - piov->from) % (off_t)PAGE_SIZE))
			return false;
		if (piov->storage != VMA_IO_ZERO)
			has_file_backed = true;

		for (i = 0; i < piov->nr; i++) {
			if ((uintptr_t)piov->to[i].iov_base % PAGE_SIZE ||
			    piov->to[i].iov_len % PAGE_SIZE)
				return false;
			if (destination_bytes >
			    UINT64_MAX - piov->to[i].iov_len)
				return false;
			destination_bytes += piov->to[i].iov_len;
		}
		if (piov->storage != VMA_IO_ZERO &&
		    destination_bytes != (uint64_t)(piov->end - piov->from))
			return false;
	}

	return has_file_backed;
}

static int maybe_read_page_local(struct page_read *pr, unsigned long vaddr, unsigned long nr, void *buf, unsigned flags)
{
	int ret;
	unsigned long len = nr * PAGE_SIZE;

	/*
	 * There's no API in the kernel to start asynchronous
	 * cached read (or write), so in case someone is asking
	 * for us for urgent async read, just do the regular
	 * cached read.
	 */
	if ((flags & (PR_ASYNC | PR_ASAP)) == PR_ASYNC)
		ret = pagemap_enqueue_iovec(pr, buf, len, &pr->async);
	else {
		ret = read_local_page(pr, vaddr, len, buf);
		if (ret == 0 && pr->io_complete)
			ret = pr->io_complete(pr, vaddr, nr);
	}

	pr->pi_off += len;

	return ret;
}

int pread_full(int fd, void *buf, size_t count, off_t offset)
{
	size_t rd = 0;

	while (rd < count) {
		ssize_t ret = pread(fd, (char *)buf + rd, count - rd, offset + rd);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			pr_perror("Short pread %zd/%zu at offset %lld",
				  ret, count, (long long)(offset + rd));
			return -1;
		}
		if (ret == 0) {
			pr_err("Short pread %zu/%zu at offset %lld\n",
			       rd, count, (long long)(offset + rd));
			return -1;
		}
		rd += ret;
	}
	return 0;
}

/*
 * Advance compressed offset tracking by @nr pages without
 * reading any data. Used when enqueuing async compressed reads.
 *
 * Caller has already verified that @nr aligns to block boundaries
 * (start at block 0 offset, end on block boundary or entry end) and
 * that pr->blk.block_offset is 0 in block mode.
 */
static void skip_compressed_offsets(struct page_read *pr, unsigned long nr)
{
	if (advance_compressed_offsets(pr, nr))
		BUG();
}

static bool block_cache_hit(struct page_read *pr, unsigned long vaddr,
			    size_t size)
{
	return pr->blk.cache_size == size &&
	       pr->blk.cache_vaddr == vaddr;
}

static int block_cache_load(struct page_read *pr, int fd, char *compressed_buf,
			    unsigned long vaddr, size_t idx, uint32_t cs,
			    unsigned int pages, size_t bytes)
{
	char *cache;
	size_t old_size = pr->blk.cache_size;

	/* Do not expose partially overwritten data as a valid cache entry. */
	pr->blk.cache_size = 0;

	if (bytes != old_size) {
		cache = xrealloc(pr->blk.cache_buf, bytes);
		if (!cache)
			return -1;
		pr->blk.cache_buf = cache;
	}

	if (pread_full(fd, compressed_buf, cs, pr->pi_off))
		return -1;

	if (decompress_block(compressed_buf, cs, pages, pr->blk.cache_buf)) {
		pr_err("Block decompression failed (idx=%zu cs=%u block=%u)\n",
		       idx, cs, pages);
		return -1;
	}

	pr->blk.cache_vaddr = vaddr;
	pr->blk.cache_size = bytes;
	return 0;
}

/*
 * Synchronous compressed page read. Each block_sizes[]
 * entry covers up to pages_per_block pages. Reads may start mid-block
 * (when pr->blk.block_offset > 0) and may end mid-block.
 *
 * For each block touched, read its compressed bytes, decompress into
 * a heap scratch buffer once, then memcpy the requested page slice
 * out. Crossing a block boundary advances pr->blk.block_idx
 * and pr->pi_off; staying within a block bumps block_offset.
 */
static int read_compressed_pages(struct page_read *pr, int fd,
				 unsigned long vaddr, unsigned long nr,
				 void *buf)
{
	unsigned long pages_done = 0;
	size_t scratch_cap = 0;
	int rc = -1;
	char *scratch = NULL;

	while (pages_done < nr) {
		size_t idx = pr->blk.block_idx;
		uint32_t cs;
		unsigned int this_block;
		size_t this_bytes;
		unsigned int off = pr->blk.block_offset;
		unsigned int avail;
		unsigned int take;
		size_t out_bytes;
		unsigned long block_vaddr;

		if (!pr->pe->blocks || idx >= pr->pe->blocks->n_block_sizes) {
			pr_err("block read: index %zu >= n_compressed %zu\n",
			       idx, pr->pe->blocks ? pr->pe->blocks->n_block_sizes : 0);
			goto out;
		}

		cs = pr->pe->blocks->block_sizes[idx];
		this_block = current_block_pages(pr);
		this_bytes = (size_t)this_block * PAGE_SIZE;

		if ((size_t)cs > this_bytes) {
			pr_err("Invalid block compressed size %u (block=%u idx=%zu)\n",
			       cs, this_block, idx);
			goto out;
		}

		avail = this_block - off;
		take = avail;
		if (nr - pages_done < avail)
			take = (unsigned int)(nr - pages_done);
		out_bytes = (size_t)take * PAGE_SIZE;
		block_vaddr = vaddr + pages_done * PAGE_SIZE -
				 (unsigned long)off * PAGE_SIZE;

		if (cs == 0) {
			memset((char *)buf + pages_done * PAGE_SIZE, 0, out_bytes);
		} else if ((size_t)cs == this_bytes) {
			/* Stored raw: pread directly the requested slice. */
			if (pread_full(fd,
				       (char *)buf + pages_done * PAGE_SIZE,
				       out_bytes,
				       pr->pi_off + (off_t)off * PAGE_SIZE))
				goto out;
		} else if (off == 0 && take == this_block) {
			char *new_scratch;

			/* Whole block in one go: decompress straight into the dest. */
			if (scratch_cap < cs) {
				new_scratch = xrealloc(scratch, cs);
				if (!new_scratch)
					goto out;
				scratch = new_scratch;
				scratch_cap = cs;
			}
			if (pread_full(fd, scratch, cs, pr->pi_off))
				goto out;
			if (decompress_block(scratch, cs, this_block,
					     (char *)buf + pages_done * PAGE_SIZE)) {
				pr_err("Block decompression failed (idx=%zu cs=%u block=%u)\n",
				       idx, cs, this_block);
				goto out;
			}
		} else {
			char *new_scratch;

			/*
			 * Partial slice: keep the decompressed block around
			 * because incremental restores can read alternating
			 * pages from the same parent block.
			 */
			if (!block_cache_hit(pr, block_vaddr, this_bytes)) {
				if (scratch_cap < cs) {
					new_scratch = xrealloc(scratch, cs);
					if (!new_scratch)
						goto out;
					scratch = new_scratch;
					scratch_cap = cs;
				}
				if (block_cache_load(pr, fd, scratch, block_vaddr, idx,
						     cs, this_block, this_bytes))
					goto out;
			}
			memcpy((char *)buf + pages_done * PAGE_SIZE,
			       pr->blk.cache_buf + (size_t)off * PAGE_SIZE,
			       out_bytes);
		}

		pages_done += take;
		pr->blk.block_offset = off + take;

		if (pr->blk.block_offset == this_block) {
			pr->pi_off += cs;
			pr->blk.block_idx++;
			pr->blk.block_offset = 0;
		}
	}

	rc = 0;
out:
	xfree(scratch);
	return rc;
}

static int maybe_read_page_local_compressed(struct page_read *pr, unsigned long vaddr, unsigned long nr, void *buf, unsigned flags)
{
	int fd, ret;
	unsigned long len = nr * PAGE_SIZE;
	unsigned int block_pages;

	/*
	 * If this pagemap entry has no block sizes array, it
	 * was stored uncompressed (e.g. shared memory pagemaps or
	 * entries from a non-compressed parent). Fall back to the
	 * normal uncompressed reader.
	 */
	if (!pr->pe->blocks)
		return maybe_read_page_local(pr, vaddr, nr, buf, flags);

	block_pages = pagemap_block_pages(pr->pe);

	/*
	 * block_pages comes from the image and sizes the block scratch
	 * buffers and a uint16_t block_pages[]; reject a value the dump
	 * side would never write before it drives a huge allocation or
	 * truncates silently.
	 */
	if (block_pages > MAX_BLOCK_PAGES) {
		pr_err("Invalid block_pages %u in pagemap (max %lu)\n",
		       block_pages, MAX_BLOCK_PAGES);
		return -1;
	}

	/*
	 * For PR_ASYNC (without PR_ASAP), enqueue the request.
	 * The compressed_size metadata is captured by
	 * pagemap_enqueue_iovec(); actual decompression happens
	 * later in process_async_reads(). This batches many
	 * small reads into fewer large pread() calls.
	 *
	 * Block mode async requires the request to align to block
	 * boundaries (start at offset 0 in a block; finish on a block
	 * boundary or at the entry's end). Mid-block async requests
	 * fall through to the sync path.
	 */
	if ((flags & (PR_ASYNC | PR_ASAP)) == PR_ASYNC) {
		uint64_t pages_consumed = (uint64_t)pr->blk.block_idx * block_pages;
		uint64_t end_page = pages_consumed + nr;
		bool can_async = (pr->blk.block_offset == 0) &&
				 (nr % block_pages == 0 ||
				  end_page == pr->pe->nr_pages);

		if (can_async) {
			ret = pagemap_enqueue_iovec(pr, buf, len, &pr->async);
			if (ret)
				return ret;
			skip_compressed_offsets(pr, nr);
			return 0;
		}
		/* Mid-block or unaligned: fall back to sync. */
	}

	fd = img_raw_fd(pr->pi);
	if (fd < 0) {
		pr_err("Failed getting raw image fd\n");
		return -1;
	}

	/*
	 * Flush any pending async requests not to break the
	 * linear reading from the pages.img file.
	 */
	if (pr->sync(pr))
		return -1;

	pr_debug("\tpr%lu-%u Read page from self %lx/%" PRIx64 "\n",
		 pr->img_id, pr->id, pr->cvaddr, pr->pi_off);

	ret = read_compressed_pages(pr, fd, vaddr, nr, buf);
	if (ret)
		return ret;

	if (pr->io_complete)
		ret = pr->io_complete(pr, vaddr, nr);

	return ret;
}

/*
 * We cannot use maybe_read_page_local() for streaming images as it uses
 * pread(), seeking in the file. Instead, we use this custom page reader.
 */
static int maybe_read_page_img_streamer(struct page_read *pr, unsigned long vaddr, unsigned long nr, void *buf, unsigned flags)
{
	unsigned long len = nr * PAGE_SIZE;
	int fd;
	int ret;
	size_t curr = 0;

	fd = img_raw_fd(pr->pi);
	if (fd < 0) {
		pr_err("Getting raw FD failed\n");
		return -1;
	}
	while (pr->stream_padding) {
		char discard[PAGE_PADDING_CHUNK];
		size_t chunk = min(pr->stream_padding, sizeof(discard));

		ret = read(fd, discard, chunk);
		if (ret == 0) {
			pr_err("Reached EOF while skipping page-image alignment\n");
			return -1;
		}
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			pr_perror("Can't skip page-image alignment");
			return -1;
		}
		pr->stream_padding -= ret;
	}

	pr_debug("\tpr%lu-%u Read page from self %lx/%" PRIx64 "\n", pr->img_id, pr->id, pr->cvaddr, pr->pi_off);

	/* We can't seek. The requested address better match */
	BUG_ON(pr->cvaddr != vaddr);

	while (1) {
		ret = read(fd, buf + curr, len - curr);
		if (ret == 0) {
			pr_err("Reached EOF unexpectedly while reading page from image\n");
			return -1;
		} else if (ret < 0) {
			pr_perror("Can't read mapping page %d", ret);
			return -1;
		}
		curr += ret;
		if (curr == len)
			break;
	}

	if (opts.auto_dedup)
		pr_warn_once("Can't dedup when streaming images\n");

	if (pr->io_complete)
		ret = pr->io_complete(pr, vaddr, nr);

	pr->pi_off += len;

	return ret;
}

/*
 * Restore one compressed pagemap extent from a forward-only image stream.
 *
 * Unlike the local-image path, this reader cannot pread individual blocks or
 * retry them out of order. It therefore validates each bounded metadata batch
 * before consuming the corresponding packed payload, reads that payload once,
 * and keeps it alive until every LZ4 worker has completed. Zero and raw pages
 * are materialized inline; only LZ4-compressed pages enter the persistent worker
 * pool. Reader offsets and the compressed-size cursor are committed only after
 * the entire requested extent is decoded; io_complete runs before publication.
 *
 * Entries whose metadata was elided because every page was stored raw retain
 * the ordinary streaming representation and use maybe_read_page_img_streamer().
 */
static int maybe_read_page_img_streamer_compressed(struct page_read *pr, unsigned long vaddr, unsigned long nr, void *buf, unsigned flags)
{
	struct page_read *owner = pr->blk.encoded_owner;
	struct encoded_read_ctx *ctx = NULL;
	uint64_t total_payload = 0;
	unsigned long pages_done = 0;
	ssize_t bytes;
	int fd;
	int ret = -1;

	/* Select the representation before consuming alignment or payload bytes. */
	if (!pr->pe->blocks)
		return maybe_read_page_img_streamer(pr, vaddr, nr, buf, flags);

	if (pr->pe->blocks->pages_per_block > 1) {
		pr_err("Streaming restore does not support multi-page block compression\n");
		return -1;
	}

	fd = img_raw_fd(pr->pi);
	if (fd < 0) {
		pr_err("Getting raw FD failed\n");
		return -1;
	}
	while (pr->stream_padding) {
		char discard[PAGE_PADDING_CHUNK];
		size_t chunk = min(pr->stream_padding, sizeof(discard));

		bytes = read(fd, discard, chunk);
		if (bytes == 0) {
			pr_err("Reached EOF while skipping compressed page-image alignment\n");
			return -1;
		}
		if (bytes < 0) {
			if (errno == EINTR)
				continue;
			pr_perror("Can't skip compressed page-image alignment");
			return -1;
		}
		pr->stream_padding -= bytes;
	}

	pr_debug("\tpr%lu-%u Read page from self %lx/%" PRIx64 "\n",
		 pr->img_id, pr->id, pr->cvaddr, pr->pi_off);

	BUG_ON(pr->cvaddr != vaddr);

	if (pr->blk.block_idx > pr->pe->blocks->n_block_sizes ||
	    nr > pr->pe->blocks->n_block_sizes - pr->blk.block_idx) {
		pr_err("Compressed size index out of bounds: %zu + %lu > %zu\n",
		       pr->blk.block_idx, nr,
		       pr->pe->blocks->n_block_sizes);
		return -1;
	}
	if (pr->pi_off < 0) {
		pr_err("Invalid negative compressed stream offset: %jd\n",
		       (intmax_t)pr->pi_off);
		return -1;
	}

	while (pages_done < nr) {
		unsigned long batch_pages = min(nr - pages_done,
						 ASYNC_BATCH_MAX_PAGES);
		size_t first = pr->blk.block_idx + pages_done;
		size_t batch_payload = 0;
		size_t nr_jobs = 0;
		size_t i;

		/* Validate and size the batch before consuming any bytes. */
		for (i = 0; i < batch_pages; i++) {
			uint32_t cs = pr->pe->blocks->block_sizes[first + i];

			if (cs > PAGE_SIZE) {
				pr_err("Invalid compressed size %u for page %zu\n",
				       cs, first + i);
				goto out;
			}
			if (batch_payload > ASYNC_BATCH_MAX_BYTES - cs) {
				pr_err("Compressed streaming batch exceeds %lu bytes\n",
				       ASYNC_BATCH_MAX_BYTES);
				goto out;
			}
			batch_payload += cs;
			if (cs && cs < PAGE_SIZE)
				nr_jobs++;
		}

		if (total_payload > (uint64_t)OFF_MAX - (uint64_t)pr->pi_off ||
		    batch_payload > (uint64_t)OFF_MAX - (uint64_t)pr->pi_off -
					 total_payload) {
			pr_err("Compressed stream offset overflows at page %zu\n", first);
			goto out;
		}

		/* Lazily reserve one working set and reuse it for this active read. */
		if (batch_payload || nr_jobs) {
			if (!owner) {
				pr_err("Streaming page reader has no encoded-read context owner\n");
				goto out;
			}
			if (!owner->blk.encoded_ctx)
				owner->blk.encoded_ctx = encoded_read_ctx_alloc();
			if (!owner->blk.encoded_ctx)
				goto out;
			ctx = owner->blk.encoded_ctx;
		}

		if (encoded_stream_read_batch(fd, (char *)buf + pages_done * PAGE_SIZE,
					      &pr->pe->blocks->block_sizes[first],
					      batch_pages, batch_payload, nr_jobs, ctx, first) < 0)
			goto out;

		total_payload += batch_payload;
		pages_done += batch_pages;
	}

	/* Publish completion before advancing externally visible stream cursors. */
	ret = 0;
	if (pr->io_complete)
		ret = pr->io_complete(pr, vaddr, nr);

	pr->pi_off += (off_t)total_payload;
	pr->blk.block_idx += nr;

out:
	encoded_read_ctx_end_work(ctx);
	return ret;
}

static int read_page_complete(unsigned long img_id, unsigned long vaddr, unsigned long int nr_pages, void *priv)
{
	int ret = 0;
	struct page_read *pr = priv;

	if (pr->img_id != img_id) {
		pr_err("Out of order read completed (want %lu have %lu)\n", pr->img_id, img_id);
		return -1;
	}

	if (pr->io_complete)
		ret = pr->io_complete(pr, vaddr, nr_pages);
	else
		pr_warn_once("Remote page read w/o io_complete!\n");

	return ret;
}

static int maybe_read_page_remote(struct page_read *pr, unsigned long vaddr, unsigned long nr, void *buf, unsigned flags)
{
	int ret;

	/* We always do PR_ASAP mode here (FIXME?) */
	ret = request_remote_pages(pr->img_id, vaddr, nr);
	if (!ret)
		ret = page_server_start_read(buf, nr, read_page_complete, pr, flags);
	return ret;
}

static int read_pagemap_page(struct page_read *pr, unsigned long vaddr, unsigned long nr, void *buf, unsigned flags)
{
	pr_info("pr%lu-%u Read %lx %lu pages\n", pr->img_id, pr->id, vaddr, nr);
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
	pr->pmes = NULL;
}

static void advance_piov(struct page_read_iov *piov, ssize_t len)
{
	ssize_t olen = len;
	int onr = piov->nr;
	unsigned int consumed = 0;

	piov->from += len;

	while (consumed < piov->nr &&
	       piov->to[consumed].iov_len <= (size_t)len) {
		len -= piov->to[consumed].iov_len;
		consumed++;
	}

	if (consumed) {
		piov->nr -= consumed;
		if (piov->nr)
			memmove(piov->to, piov->to + consumed,
				piov->nr * sizeof(*piov->to));
	}
	if (len) {
		BUG_ON(!piov->nr);
		piov->to[0].iov_base =
			(char *)piov->to[0].iov_base + len;
		piov->to[0].iov_len -= len;
	}

	pr_debug("Advanced iov %zd bytes, %d->%d iovs, %zd tail\n",
		 olen, onr, piov->nr, len);
}

/*
 * Drain (free without reading) all async entries in pr and its parent chain.
 * Called on error paths to satisfy BUG_ON(!list_empty(&pr->async)) in
 * close_page_read().
 */
static void drain_async_queue(struct page_read *pr)
{
	struct page_read_iov *piov, *n;

	list_for_each_entry_safe(piov, n, &pr->async, l) {
		list_del(&piov->l);
		xfree(piov->b_layout.sizes);
		xfree(piov->block_pages);
		xfree(piov->to);
		xfree(piov);
	}
	if (pr->parent)
		drain_async_queue(pr->parent);
}

static bool page_read_chain_has_encoded_async(struct page_read *pr)
{
	struct page_read_iov *piov;

	list_for_each_entry(piov, &pr->async, l) {
		if (piov->storage == VMA_IO_ENCODED)
			return true;
	}

	return pr->parent && page_read_chain_has_encoded_async(pr->parent);
}

/*
 * Drain one page-reader chain in image order. Each queue element has one of
 * four storage kinds: zero and packed raw bypass LZ4, ordinary entries use
 * preadv(), and encoded entries use the shared chain context above. Parent
 * queues share the same context. Acquire its working-set lease only when an
 * encoded request is reached. A second nonblocking lease permits one payload
 * read to overlap decoding. Release both before ordinary I/O or a parent
 * queue. Any error drains the remaining subtree before close_page_read()
 * checks that all queues are empty.
 */
static int process_async_reads_ctx(struct page_read *pr,
				   struct encoded_read_ctx *encoded_ctx)
{
	int fd, ret = 0;
	struct page_read_iov *piov, *n;
	off_t first_off = OFF_MAX, last_end = OFF_MIN;

	fd = img_raw_fd(pr->pi);
	/* Hint bounded nearby ranges before issuing their explicit preadv calls. */
	if (!pr->use_direct) {
		list_for_each_entry(piov, &pr->async, l) {
			bool merge = first_off != OFF_MAX &&
				     piov->from >= last_end &&
				     piov->from - last_end <= ASYNC_READAHEAD_MAX_GAP &&
				     piov->end - first_off <= ASYNC_READAHEAD_MAX_BYTES;

			if (!merge && last_end > first_off) {
				if (posix_fadvise(fd, first_off, last_end - first_off, POSIX_FADV_WILLNEED) != 0)
					pr_debug("posix_fadvise(WILLNEED) failed for async range\n");
				first_off = OFF_MAX;
				last_end = OFF_MIN;
			}
			if (first_off == OFF_MAX) {
				first_off = piov->from;
				last_end = piov->end;
			} else {
				last_end = max(piov->end, last_end);
			}
		}
		if (last_end > first_off) {
			if (posix_fadvise(fd, first_off, last_end - first_off, POSIX_FADV_WILLNEED) != 0)
				pr_debug("posix_fadvise(WILLNEED) failed for async range\n");
		}
	}

	/* Consume and free each request only after its destination is complete. */
	list_for_each_entry_safe(piov, n, &pr->async, l) {
		ssize_t ret;
		struct iovec *iovs = piov->to;

		pr_debug("Read piov iovs %d, from %ju, len %ju, first %p:%zu\n", piov->nr, piov->from,
			 piov->end - piov->from, piov->to->iov_base, piov->to->iov_len);

		/* Do not occupy an encoded-work slot while serving ordinary ranges. */
		if (piov->storage != VMA_IO_ENCODED)
			encoded_read_ctx_end_work(encoded_ctx);

		if (piov->storage == VMA_IO_ZERO) {
			if (validate_direct_compressed_iov(piov)) {
				ret = -1;
				goto err;
			}
			for (unsigned int i = 0; i < piov->nr; i++)
				memset(piov->to[i].iov_base, 0, piov->to[i].iov_len);
			goto next;
		}

		if (piov->storage == VMA_IO_PACKED_RAW) {
			if (validate_direct_compressed_iov(piov)) {
				ret = -1;
				goto err;
			}
			goto more;
		}

		if (piov->storage == VMA_IO_ENCODED) {
			bool is_last = list_is_last(&piov->l, &pr->async);

			ret = encoded_async_read_batch(fd, piov, is_last ? NULL : n,
						       is_last, encoded_ctx, pr);
			if (ret < 0)
				goto err;
			goto next;
		}
		if (piov->storage != VMA_IO_UNCOMPRESSED) {
			pr_err("Unknown async I/O storage kind %d\n",
			       piov->storage);
			ret = -1;
			goto err;
		}

	more:
		ret = preadv(fd, piov->to, piov->nr, piov->from);
		if (fault_injected(FI_PARTIAL_PAGES)) {
			/*
			 * We might have read everything, but for debug
			 * purposes let's try to force the advance_piov()
			 * and re-read tail.
			 */
			if (ret >= 2 * PAGE_SIZE) {
				pr_debug("`- trim preadv %zu\n", ret);
				ret /= 2;
				ret &= PAGE_MASK;
			}
		}

		if (ret < 0) {
			pr_err("Can't read async pr bytes (%zd / %ju read, %ju off, %d iovs)\n", ret,
			       piov->end - piov->from, piov->from, piov->nr);
			goto err;
		}

		if (ret == 0 && piov->end != piov->from) {
			pr_err("Unexpected EOF reading pages: expected %ju more bytes at offset %ju\n",
			       piov->end - piov->from, piov->from);
			goto err;
		}

		if (opts.auto_dedup && piov->storage != VMA_IO_PACKED_RAW &&
		    punch_hole(pr, piov->from, ret, false))
			goto err;

		if (ret != piov->end - piov->from) {
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

	next:
		BUG_ON(pr->io_complete); /* FIXME -- implement once needed */
		list_del(&piov->l);
		xfree(piov->b_layout.sizes);
		xfree(piov->block_pages);
		xfree(iovs);
		xfree(piov);
	}
	/* Parent readahead and raw prefixes must not inherit an idle lease. */
	encoded_read_ctx_end_work(encoded_ctx);
	if (pr->parent) {
		ret = process_async_reads_ctx(pr->parent, encoded_ctx);
		if (ret)
			return ret;
	}

	/*
	 * A final auto-dedup batch used to be deferred until close(), whose
	 * void callback cannot report a failed fallocate(). Flush it while the
	 * caller can still propagate the error from ->sync().
	 */
	if (pr->bunch.iov_len > 0) {
		ret = punch_hole(pr, 0, 0, true);
		if (ret)
			return ret;
		pr->bunch.iov_len = 0;
	}

	return ret;
err:
	drain_async_queue(pr);
	return -1;
}

static int process_async_reads(struct page_read *pr)
{
	struct page_read *owner = pr->blk.encoded_owner;
	struct encoded_read_ctx *ctx = NULL;
	int ret;

	if (!owner) {
		pr_err("Page reader has no encoded-read context owner\n");
		drain_async_queue(pr);
		return -1;
	}

	/* Raw/zero/uncompressed-only syncs need neither buffers nor a lease. */
	if (page_read_chain_has_encoded_async(pr)) {
		if (!owner->blk.encoded_ctx)
			owner->blk.encoded_ctx = encoded_read_ctx_alloc();
		if (!owner->blk.encoded_ctx) {
			drain_async_queue(pr);
			return -1;
		}
		ctx = owner->blk.encoded_ctx;
	}

	ret = process_async_reads_ctx(pr, ctx);
	encoded_read_ctx_end_work(ctx);
	return ret;
}

static void close_page_read(struct page_read *pr)
{
	BUG_ON(!list_empty(&pr->async));
	/*
	 * Restore tasks close their page readers before they fork children or
	 * remap the PIE bootstrap. Page-server readers close after their last
	 * sync, so one pool also spans its bounded decode chunks.
	 */
	if (pr->blk.encoded_owner == pr) {
		encoded_read_ctx_destroy(pr->blk.encoded_ctx);
		pr->blk.encoded_ctx = NULL;
	}

	if (pr->bunch.iov_len > 0) {
		/* punch_hole() logs failures; cleanup must run in either case. */
		(void)punch_hole(pr, 0, 0, true);
		pr->bunch.iov_len = 0;
	}

	if (pr->parent) {
		pr->parent->close(pr->parent);
		xfree(pr->parent);
	}

	if (pr->pmi)
		close_image(pr->pmi);
	if (pr->pi)
		close_image(pr->pi);
	if (pr->pmes) {
		int i;
		for (i = 0; i < pr->nr_pmes; i++)
			pagemap_entry__free_unpacked(pr->pmes[i], NULL);
		xfree(pr->pmes);
	}

	page_read_free_cache(pr);
}

static void reset_pagemap(struct page_read *pr)
{
	pr->cvaddr = 0;
	pr->pi_off = 0;
	pr->stream_padding = 0;
	pr->blk.block_idx = 0;
	pr->blk.block_offset = 0;
	pr->curr_pme = -1;
	pr->pe = NULL;

	/* FIXME: take care of bunch */

	if (pr->parent)
		reset_pagemap(pr->parent);
}

static int open_pagemap_parent(int dfd, int *pfd)
{
	struct stat st;

	*pfd = -1;
	if (fstatat(dfd, CR_PARENT_LINK, &st, AT_SYMLINK_NOFOLLOW)) {
		if (errno == ENOENT)
			return 0;
		return -errno;
	}

	/*
	 * Unlike generic image opens, parent pagemap opens are optional during
	 * joined-userns restore. Do not route this through usernsd: the caller
	 * tolerates inaccessible parents and restore will fail later only if a
	 * required page really has to be read from that parent image.
	 */
	*pfd = openat(dfd, CR_PARENT_LINK, O_RDONLY);
	if (*pfd < 0)
		return -errno;

	return 0;
}

/*
 * Open one optional parent reader. Until the final assignment to pr->parent,
 * this function owns both the parent-directory fd and the allocated reader;
 * each failure label releases exactly the resources acquired above it.
 */
static int try_open_parent(int dfd, unsigned long id, struct page_read *pr, int pr_flags)
{
	int pfd, ret;
	struct page_read *parent = NULL;

	/* Image streaming lacks support for incremental images */
	if (opts.stream)
		goto out;

	ret = open_pagemap_parent(dfd, &pfd);
	if (ret < 0) {
		int err = -ret;

		if (opts.mode == CR_RESTORE && userns_join_ns_requested() &&
		    (err == ENOENT || err == EPERM || err == EACCES)) {
			pr_warn("Can't open parent page images in joined userns, trying current images only\n");
			goto out;
		}
		errno = err;
		pr_perror("Can't open parent path");
		goto err;
	}
	if (pfd < 0)
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
err:
	return -1;
}

static void set_encoded_read_owner(struct page_read *pr,
				   struct page_read *owner)
{
	pr->blk.encoded_owner = owner;
	if (pr->parent)
		set_encoded_read_owner(pr->parent, owner);
}

static void init_compat_pagemap_entry(PagemapEntry *pe)
{
	/*
	 * pagemap image generated with older version will either
	 * contain a hole because the pages are in the parent
	 * snapshot or a pagemap that should be marked with
	 * PE_PRESENT
	 */
	if (pe->has_in_parent && pe->in_parent)
		pe->flags |= PE_PARENT;
	else if (!pe->has_flags)
		pe->flags = PE_PRESENT;

	if (!pe->has_nr_pages)
		pe->nr_pages = pe->compat_nr_pages;
}

static bool pagemap_entry_has_compressed(PagemapEntry *pe)
{
	return pagemap_present(pe) && pe->blocks && pe->blocks->n_block_sizes;
}

static int validate_compressed_pagemap_entry(PagemapEntry *pe)
{
	uint64_t expected_blocks, sum = 0;
	unsigned int pages_per_block;
	size_t i;

	if (!pe->blocks)
		return 0;

	pages_per_block = pe->blocks->pages_per_block;

#ifndef CONFIG_LZ4
	pr_err("Pagemap contains compressed pages but CRIU was built without LZ4 support (CONFIG_LZ4)\n");
	return -1;
#endif

	if (!pagemap_present(pe)) {
		pr_err("Compressed metadata on non-present pagemap entry %#" PRIx64 "\n",
		       pe->vaddr);
		return -1;
	}

	if (!pages_per_block || pages_per_block > MAX_BLOCK_PAGES) {
		pr_err("Compressed pagemap entry %#" PRIx64
		       " has invalid pages_per_block %u (valid range 1..%lu)\n",
		       pe->vaddr, pages_per_block, MAX_BLOCK_PAGES);
		return -1;
	}
	expected_blocks = block_nr_blocks(pe->nr_pages, pages_per_block);

	if (expected_blocks > SIZE_MAX ||
	    pe->blocks->n_block_sizes != (size_t)expected_blocks) {
		pr_err("Compressed pagemap entry %#" PRIx64 " has %zu blocks, expected %" PRIu64 "\n",
		       pe->vaddr, pe->blocks->n_block_sizes, expected_blocks);
		return -1;
	}

	for (i = 0; i < pe->blocks->n_block_sizes; i++) {
		uint32_t cs = pe->blocks->block_sizes[i];
		size_t block_bytes;
		uint64_t pages_done = (uint64_t)i * pages_per_block;
		uint64_t pages_left = pe->nr_pages - pages_done;
		unsigned int cur_pages = pages_per_block;

		if (pages_left < pages_per_block)
			cur_pages = (unsigned int)pages_left;

		block_bytes = (size_t)cur_pages * PAGE_SIZE;

		/*
		 * The writer stores a block raw once LZ4 no longer saves space, so
		 * an on-image block can never be larger than its decoded contents.
		 * Enforce that before any reader uses compressed_size as an I/O size.
		 */
		if ((size_t)cs > block_bytes) {
			pr_err("Compressed pagemap entry %#" PRIx64
			       " block %zu size %u exceeds decoded size %zu\n",
			       pe->vaddr, i, cs, block_bytes);
			return -1;
		}

		if (sum > UINT64_MAX - cs) {
			pr_err("Compressed pagemap entry %#" PRIx64 " size sum overflows\n",
			       pe->vaddr);
			return -1;
		}
		sum += cs;
	}

	if (pe->blocks->total_payload_size != sum) {
		pr_err("Compressed pagemap entry %#" PRIx64 " total size %" PRIu64 " != sum %" PRIu64 "\n",
		       pe->vaddr, pe->blocks->total_payload_size, sum);
		return -1;
	}

	return 0;
}

static int validate_pagemap_entry_layout(PagemapEntry *pe,
					 uint64_t *previous_end)
{
	uint64_t length;
	uint64_t end;

	if (pagemap_payload_aligned(pe) && !pagemap_present(pe)) {
		pr_err("Aligned payload flag on non-present pagemap entry %#" PRIx64
		       "\n", pe->vaddr);
		return -1;
	}
	if (pagemap_present(pe) && pagemap_in_parent(pe)) {
		pr_err("Pagemap entry %#" PRIx64
		       " cannot be present and inherited at the same time\n",
		       pe->vaddr);
		return -1;
	}

	if (pe->vaddr % PAGE_SIZE) {
		pr_err("Pagemap entry address %#" PRIx64 " is not page-aligned\n",
		       pe->vaddr);
		return -1;
	}
	if (!pe->nr_pages) {
		pr_err("Pagemap entry %#" PRIx64 " has no pages\n", pe->vaddr);
		return -1;
	}
	if (pe->nr_pages > UINT64_MAX / PAGE_SIZE) {
		pr_err("Pagemap entry %#" PRIx64 " page count overflows\n",
		       pe->vaddr);
		return -1;
	}
	length = pe->nr_pages * PAGE_SIZE;
	if (pe->vaddr > UINT64_MAX - length) {
		pr_err("Pagemap entry %#" PRIx64 " end overflows\n", pe->vaddr);
		return -1;
	}
	end = pe->vaddr + length;
	if (pe->vaddr > ULONG_MAX || end > ULONG_MAX) {
		pr_err("Pagemap entry %#" PRIx64 "-%#" PRIx64
		       " does not fit in an address\n", pe->vaddr, end);
		return -1;
	}
	if (pe->vaddr < *previous_end) {
		pr_err("Pagemap entry %#" PRIx64 "-%#" PRIx64
		       " overlaps or precedes the previous entry ending at %#" PRIx64 "\n",
		       pe->vaddr, end, *previous_end);
		return -1;
	}

	*previous_end = end;
	return 0;
}

static int validate_pages_image_layout(PagemapEntry *pe, off_t *offset)
{
	uint64_t payload = 0;
	size_t i;

	if (!pagemap_present(pe))
		return 0;

	if (pagemap_payload_aligned(pe)) {
		if (*offset < 0 || *offset > OFF_MAX - (PAGE_SIZE - 1)) {
			pr_err("Pages image offset %jd cannot be page-aligned for entry %#" PRIx64 "\n",
			       (intmax_t)*offset, pe->vaddr);
			return -1;
		}
		*offset = pagemap_page_align_offset(*offset);
	}

	if (pe->blocks) {
		for (i = 0; i < pe->blocks->n_block_sizes; i++)
			payload += pe->blocks->block_sizes[i];
	} else {
		payload = pe->nr_pages * PAGE_SIZE;
	}
	if (payload > (uint64_t)(OFF_MAX - *offset)) {
		pr_err("Pages image payload for entry %#" PRIx64
		       " exceeds the representable file offset\n", pe->vaddr);
		return -1;
	}
	*offset += (off_t)payload;
	return 0;
}

static bool page_read_has_compressed_entries(struct page_read *pr)
{
	int i;

	for (i = 0; i < pr->nr_pmes; i++) {
		if (pagemap_entry_has_compressed(pr->pmes[i]))
			return true;
	}

	return false;
}

/*
 * Inspect [start, end) without advancing any page-reader cursor.  Return 1
 * when an overlapping block requires LZ4 decoding.  With @premap_mixed, also
 * request premapping when splitting raw and zero blocks would exceed the
 * bounded number of direct restorer jobs, or when a large zero run can use
 * parallel filling. Parent entries are inspected in their owning reader.
 * Return 0 when PIE can restore the range directly and -1 for invalid metadata.
 */
static int page_read_range_needs_decode(struct page_read *pr,
					unsigned long start,
					unsigned long end,
					bool premap_mixed)
{
	unsigned int direct_runs = 0;
	unsigned int previous_block_pages = 0;
	enum restore_vma_io_storage previous_storage = VMA_IO_UNCOMPRESSED;
	bool have_previous_storage = false;
	bool parallel_zero = false;
	int left = 0;
	int right;
	int i;

	if (!pr || start >= end || start % PAGE_SIZE || end % PAGE_SIZE) {
		pr_err("Invalid compressed-page range %#lx-%#lx\n", start, end);
		return -1;
	}
	if (premap_mixed)
		parallel_zero = compressed_restore_has_parallel_capacity(opts.decompress_threads);

	/* Find the first pagemap entry whose end is after start. */
	right = pr->nr_pmes;
	while (left < right) {
		int middle = left + (right - left) / 2;
		PagemapEntry *pe = pr->pmes[middle];
		unsigned long pe_start =
			(unsigned long)decode_pointer(pe->vaddr);
		unsigned long pe_end = pe_start + pagemap_len(pe);

		if (pe_end <= start)
			left = middle + 1;
		else
			right = middle;
	}

	/* Classify only the compressed blocks that overlap the requested range. */
	for (i = left; i < pr->nr_pmes; i++) {
		PagemapEntry *pe = pr->pmes[i];
		unsigned long pe_start =
			(unsigned long)decode_pointer(pe->vaddr);
		unsigned long pe_end = pe_start + pagemap_len(pe);
		unsigned long overlap_start;
		unsigned long overlap_end;
		unsigned int cur_block_pages;
		unsigned long zero_bytes = 0;
		unsigned int zero_blocks = 0;
		bool parallel_zero_entry = parallel_zero;
		size_t first_block;
		size_t last_block;
		size_t block;

		if (pe_start >= end)
			break;
		if (pe_end <= start)
			continue;

		overlap_start = max(start, pe_start);
		overlap_end = min(end, pe_end);
		if (pagemap_in_parent(pe)) {
			int ret;

			if (!pr->parent) {
				pr_err("Pagemap range %#lx-%#lx has no parent reader\n",
				       overlap_start, overlap_end);
				return -1;
			}
			ret = page_read_range_needs_decode(pr->parent,
							   overlap_start,
							   overlap_end,
							   premap_mixed);
			if (ret)
				return ret;
			have_previous_storage = false;
			continue;
		}
		if (!pe->blocks) {
			have_previous_storage = false;
			continue;
		}

		cur_block_pages = pagemap_block_pages(pe);
		if (have_previous_storage &&
		    cur_block_pages != previous_block_pages)
			have_previous_storage = false;
		if (cur_block_pages) {
			uint64_t first_page =
				(overlap_start - pe_start) / PAGE_SIZE;
			uint64_t end_page =
				(overlap_end - pe_start) / PAGE_SIZE;

			if (first_page % cur_block_pages ||
			    (end_page % cur_block_pages && overlap_end != pe_end))
				parallel_zero_entry = false;
			first_block = first_page / cur_block_pages;
			last_block = block_nr_blocks(end_page, cur_block_pages);
		} else {
			first_block = (overlap_start - pe_start) / PAGE_SIZE;
			last_block = (overlap_end - pe_start) / PAGE_SIZE;
		}

		if (last_block > pe->blocks->n_block_sizes) {
			pr_err("LZ4 range block index %zu exceeds %zu blocks\n",
			       last_block, pe->blocks->n_block_sizes);
			return -1;
		}
		for (block = first_block; block < last_block; block++) {
			enum restore_vma_io_storage storage;
			unsigned int block_pages;

			if (compressed_block_storage(pe, block, &storage,
						     &block_pages))
				return -1;
			if (storage == VMA_IO_ENCODED)
				return 1;
			if (parallel_zero_entry && storage == VMA_IO_ZERO) {
				uint64_t first_page = block;
				unsigned long block_start;
				unsigned long block_end;

				if (cur_block_pages)
					first_page *= cur_block_pages;
				block_start = pe_start + first_page * PAGE_SIZE;
				block_end = block_start + (unsigned long)block_pages * PAGE_SIZE;

				if (block_start < overlap_start || block_end > overlap_end) {
					zero_bytes = 0;
					zero_blocks = 0;
				} else {
					zero_bytes += block_end - block_start;
					zero_blocks++;
					if (zero_blocks > 1 &&
					    zero_bytes >= PARALLEL_RESTORE_MIN_BATCH_BYTES)
						return 1;
				}
			} else {
				zero_bytes = 0;
				zero_blocks = 0;
			}
			/* Each storage transition creates another direct restore job. */
			if (premap_mixed &&
			    (!have_previous_storage || storage != previous_storage) &&
			    ++direct_runs > DIRECT_COMPRESSED_RUN_MAX)
				return 1;
			previous_storage = storage;
			previous_block_pages = cur_block_pages;
			have_previous_storage = true;
		}
	}

	return 0;
}

int page_read_range_has_lz4(struct page_read *pr, unsigned long start,
			     unsigned long end)
{
	return page_read_range_needs_decode(pr, start, end, false);
}

int page_read_range_needs_premap(struct page_read *pr, unsigned long start,
				  unsigned long end)
{
	return page_read_range_needs_decode(pr, start, end, true);
}

int page_read_range_has_parent(struct page_read *pr, unsigned long start,
				unsigned long end)
{
	int left = 0;
	int right;
	int i;

	if (!pr || start >= end || start % PAGE_SIZE || end % PAGE_SIZE) {
		pr_err("Invalid parent-page range %#lx-%#lx\n", start, end);
		return -1;
	}

	right = pr->nr_pmes;
	while (left < right) {
		int middle = left + (right - left) / 2;
		PagemapEntry *pe = pr->pmes[middle];
		unsigned long pe_start =
			(unsigned long)decode_pointer(pe->vaddr);
		unsigned long pe_end = pe_start + pagemap_len(pe);

		if (pe_end <= start)
			left = middle + 1;
		else
			right = middle;
	}

	for (i = left; i < pr->nr_pmes; i++) {
		PagemapEntry *pe = pr->pmes[i];
		unsigned long pe_start =
			(unsigned long)decode_pointer(pe->vaddr);
		unsigned long pe_end = pe_start + pagemap_len(pe);

		if (pe_start >= end)
			break;
		if (pe_end > start && pagemap_in_parent(pe))
			return 1;
	}

	return 0;
}

#define PAGEMAP_INITIAL_ENTRIES 64

static int init_pagemaps(struct page_read *pr)
{
	uint64_t previous_end = 0;
	off_t pages_offset = 0;
	size_t capacity = PAGEMAP_INITIAL_ENTRIES;

	pr->pmes = xzalloc(capacity * sizeof(*pr->pmes));
	if (!pr->pmes)
		return -1;

	pr->nr_pmes = 0;
	pr->curr_pme = -1;

	while (1) {
		PagemapEntry **new;
		PagemapEntry *pe;
		int ret;

		if ((size_t)pr->nr_pmes == capacity) {
			size_t alloc_size;
			size_t new_capacity;

			if (capacity >= INT_MAX ||
			    __builtin_mul_overflow(capacity, (size_t)2,
						   &new_capacity)) {
				pr_err("Too many pagemap entries\n");
				goto free_pagemaps;
			}
			new_capacity = min(new_capacity, (size_t)INT_MAX);
			if (__builtin_mul_overflow(new_capacity, sizeof(*pr->pmes),
						   &alloc_size)) {
				pr_err("Pagemap entry array size overflows\n");
				goto free_pagemaps;
			}
			new = xrealloc(pr->pmes, alloc_size);
			if (!new)
				goto free_pagemaps;
			pr->pmes = new;
			capacity = new_capacity;
		}

		ret = pb_read_one_eof(pr->pmi, &pr->pmes[pr->nr_pmes],
				      PB_PAGEMAP);
		if (ret < 0)
			goto free_pagemaps;
		if (ret == 0)
			break;

		pe = pr->pmes[pr->nr_pmes++];
		init_compat_pagemap_entry(pe);
		if (validate_pagemap_entry_layout(pe, &previous_end))
			goto free_pagemaps;
		if (validate_compressed_pagemap_entry(pe))
			goto free_pagemaps;
		if (validate_pages_image_layout(pe, &pages_offset))
			goto free_pagemaps;
	}

	close_image(pr->pmi);
	pr->pmi = NULL;

	return 0;

free_pagemaps:
	free_pagemaps(pr);
	return -1;
}

int probe_pages_o_direct(int fd)
{
	int fl, ret, memerr;
	void *probe = NULL;
	ssize_t probe_ret;

	fl = fcntl(fd, F_GETFL);
	if (fl < 0)
		return 0;

	ret = fcntl(fd, F_SETFL, fl | O_DIRECT);
	if (ret < 0) {
		pr_warn("Failed to set O_DIRECT on pages fd %d: %s\n", fd, strerror(errno));
		return 0;
	}

	/*
	 * PAGE_SIZE is not a compile-time constant on aarch64, so the
	 * probe buffer is allocated via posix_memalign() instead of a
	 * stack array with __attribute__((aligned)).
	 */
	memerr = posix_memalign(&probe, PAGE_SIZE, PAGE_SIZE);
	if (memerr) {
		pr_err("O_DIRECT probe alloc failed on pages fd %d: %s\n", fd, strerror(memerr));
		return -1;
	}

	probe_ret = pread(fd, probe, PAGE_SIZE, 0);
	xfree(probe);

	if (probe_ret >= 0) {
		pr_debug("O_DIRECT enabled on pages fd %d\n", fd);
		return 1;
	}

	if (errno != EINVAL) {
		pr_perror("O_DIRECT probe failed on pages fd %d", fd);
		return -1;
	}

	pr_warn("O_DIRECT rejected at read time on pages fd %d, using buffered I/O\n", fd);
	if (fcntl(fd, F_SETFL, fl) < 0) {
		pr_perror("Failed to clear O_DIRECT on pages fd %d", fd);
		return -1;
	}

	/*
	 * Hint the kernel that fallback buffered reads will mostly
	 * advance through the pages file in offset order.
	 */
	posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
	return 0;
}

int open_page_read_at(int dfd, unsigned long img_id, struct page_read *pr, int pr_flags)
{
	int flags, i_typ;
	/* Shared across asyncd fill-daemon workers, which open page-reads concurrently. */
	static atomic_t ids = { 0 };
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
	pr->stream_padding = 0;
	memset(&pr->blk, 0, sizeof(pr->blk));
	pr->blk.encoded_owner = pr;
	pr->bunch.iov_len = 0;
	pr->bunch.iov_base = NULL;
	pr->pmes = NULL;
	pr->pieok = false;
	pr->disable_dedup = false;
	pr->use_direct = false;

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
	set_encoded_read_owner(pr, pr);

	pr->pi = open_pages_image_at(dfd, flags, pr->pmi, &pr->pages_img_id);
	if (!pr->pi) {
		close_page_read(pr);
		return -1;
	}

	if (init_pagemaps(pr)) {
		close_page_read(pr);
		return -1;
	}

	{
		int pfd = img_raw_fd(pr->pi);

		/*
		 * O_DIRECT requires reads to be aligned in offset and
		 * length. Compressed pages are stored as variable-length
		 * blocks packed contiguously, so reads are unaligned and
		 * O_DIRECT would fail with EINVAL. Use buffered I/O for any
		 * reader whose own pagemap contains compressed entries; parent
		 * images may differ from the top inventory's compression mode.
		 */
		if (pfd >= 0 && !opts.stream && opts.image_io_mode == IMAGE_IO_DIRECT &&
		    !page_read_has_compressed_entries(pr)) {
			int direct = probe_pages_o_direct(pfd);

			if (direct < 0) {
				close_page_read(pr);
				return -1;
			}
			pr->use_direct = (direct == 1);
		}
	}

	/*
	 * Hint the kernel to use aggressive readahead on the pages
	 * image. pread() does not advance the file offset, so the
	 * kernel's sequential-access heuristic may not trigger
	 * without this hint.
	 */
	if (img_raw_fd(pr->pi) >= 0)
		posix_fadvise(img_raw_fd(pr->pi), 0, 0, POSIX_FADV_SEQUENTIAL);

	pr->read_pages = read_pagemap_page;
	pr->advance = advance;
	pr->close = close_page_read;
	pr->skip_pages = skip_pagemap_pages;
	pr->sync = process_async_reads;
	pr->seek_pagemap = seek_pagemap;
	pr->reset = reset_pagemap;
	pr->io_complete = NULL; /* set up by the client if needed */
	pr->id = atomic_inc_return(&ids);
	pr->img_id = img_id;

	if (remote)
		pr->maybe_read_page = maybe_read_page_remote;
	else if (opts.stream && page_read_has_compressed_entries(pr))
		pr->maybe_read_page = maybe_read_page_img_streamer_compressed;
	else if (opts.stream)
		pr->maybe_read_page = maybe_read_page_img_streamer;
	else {
		pr->maybe_read_page = maybe_read_page_local_compressed;
		if (!pr->parent && !opts.lazy_pages)
			pr->pieok = true;
	}

	pr_debug("Opened %s page read %u (parent %u)\n", remote ? "remote" : "local", pr->id,
		 pr->parent ? pr->parent->id : 0);

	return 1;
}

int open_page_read(unsigned long img_id, struct page_read *pr, int pr_flags)
{
	return open_page_read_at(get_service_fd(IMG_FD_OFF), img_id, pr, pr_flags);
}

#define DUP_IDS_BASE 1000

void page_read_disable_dedup(struct page_read *pr)
{
	pr_debug("disable dedup, id: %d\n", pr->id);
	pr->disable_dedup = true;
	if (pr->parent)
		page_read_disable_dedup(pr->parent);
}

void dup_page_read(struct page_read *src, struct page_read *dst)
{
	static int dup_ids = 1;

	memcpy(dst, src, sizeof(*dst));
	INIT_LIST_HEAD(&dst->async);
	dst->id = src->id + DUP_IDS_BASE * dup_ids++;
	dst->blk.cache_buf = NULL;
	dst->blk.cache_vaddr = 0;
	dst->blk.cache_size = 0;
	dst->blk.encoded_ctx = NULL;
	/*
	 * UFFD fork readers are shallow duplicates and keep their root lpi alive
	 * through its reference count. Reuse that root's chain context instead of
	 * allocating an unowned context that lpi_fini() cannot release.
	 */
	dst->blk.encoded_owner = src->blk.encoded_owner;
	dst->reset(dst);
}
