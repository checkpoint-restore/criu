/*
 * Per-thread page pool - lock-free allocation to avoid malloc/mprotect
 * contention.
 *
 * When many receiver threads allocate PAGE_SIZE buffers via malloc, glibc's
 * heap management triggers mprotect calls that serialize on the kernel's
 * mmap_sem write lock. This pool avoids that via:
 *   - Per-thread bump allocator (no locks on allocation path)
 *   - CLONE_CHUNK_SIZE-aligned chunks for O(1) chunk lookup from a page
 *     address (mask off the low bits)
 *   - Atomic refcount per chunk; munmap the chunk when refcount hits zero
 *
 * Chunk layout (CLONE_CHUNK_SIZE-aligned base):
 *   page 0  : chunk header (refcount, validation pointer)
 *   page 1+ : allocatable pages
 */

#include <sys/mman.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include <execinfo.h>
#include <stdlib.h>
#include <limits.h>

#include "page.h"
#include "clone/page-pool.h"
#include "clone/clone-conf.h"
#include "criu-log.h"
#include "common/bug.h"

#undef LOG_PREFIX
#define LOG_PREFIX "page-pool: "

/* Chunk header - stored at start of each chunk region (uses page 0) */
struct chunk_header {
	atomic_int refcount;      /* Pages still in use */
	atomic_int max_allocated; /* High-water mark of pages allocated */
	int chunk_idx;            /* Index in all_chunks array */
	void *base;               /* Self-pointer for validation */
};

/* Per-thread pool state */
struct thread_pool {
	void *current_chunk;     /* Current chunk base address */
	int next_page;           /* Next page index to allocate */
	bool initialized;
};

static struct thread_pool pools[CLONE_MAX_THREADS];
static void *all_chunks[CLONE_MAX_POOL_CHUNKS];
static atomic_int nr_chunks;
static pthread_spinlock_t chunk_list_lock;  /* Only for chunk tracking */
static atomic_bool global_init_done;
static atomic_ulong total_put_count;
static atomic_ulong total_alloc_count;
static atomic_int total_chunks_freed;

/* Allocate a new CLONE_CHUNK_SIZE-aligned chunk */
static void *alloc_chunk(void)
{
	void *chunk;
	void *raw;
	struct chunk_header *hdr;
	size_t front_excess, back_excess;
	int idx;

	/*
	 * mmap with MAP_ANONYMOUS gives page-aligned memory; over-allocate
	 * and align manually to get CLONE_CHUNK_SIZE alignment.
	 */
	raw = mmap(NULL, CLONE_CHUNK_SIZE + CLONE_CHUNK_ALIGN, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (raw == MAP_FAILED) {
		pr_perror("Failed to mmap chunk");
		BUG();
	}

	chunk = (void *)(((unsigned long)raw + CLONE_CHUNK_ALIGN - 1) & CLONE_CHUNK_ALIGN_MASK);

	/* Unmap the excess at front and back */
	front_excess = (size_t)(chunk - raw);
	back_excess = CLONE_CHUNK_ALIGN - front_excess;
	if (front_excess > 0)
		munmap(raw, front_excess);
	if (back_excess > 0)
		munmap((char *)chunk + CLONE_CHUNK_SIZE, back_excess);

	/* Initialize header (page 0) */
	hdr = (struct chunk_header *)chunk;
	atomic_init(&hdr->refcount, 0);
	atomic_init(&hdr->max_allocated, 1);
	hdr->chunk_idx = -1;
	hdr->base = chunk;

	/* Track for cleanup */
	pthread_spin_lock(&chunk_list_lock);
	idx = atomic_load(&nr_chunks);
	if (idx < CLONE_MAX_POOL_CHUNKS) {
		all_chunks[idx] = chunk;
		hdr->chunk_idx = idx;
		atomic_fetch_add(&nr_chunks, 1);
	} else {
		/* Hit limit; reuse a NULL slot from a freed chunk. */
		int reused_slot = -1;
		for (int i = 0; i < CLONE_MAX_POOL_CHUNKS; i++) {
			if (all_chunks[i] == NULL) {
				all_chunks[i] = chunk;
				hdr->chunk_idx = i;
				reused_slot = i;
				pr_debug("PAGE_POOL: Reused NULL slot %d for new chunk %p\n",
				       i, chunk);
				break;
			}
		}
		if (reused_slot < 0) {
			/* No NULL slots available - untracked chunks not supported */
			pthread_spin_unlock(&chunk_list_lock);
			pr_err("PAGE_POOL: Hit limit (%d) with no free slots\n",
			       CLONE_MAX_POOL_CHUNKS);
			munmap(chunk, CLONE_CHUNK_SIZE);
			BUG();
		}
	}
	pthread_spin_unlock(&chunk_list_lock);

	pr_debug("PAGE_POOL: Allocated chunk at %p (total: %d chunks)\n",
		 chunk, atomic_load(&nr_chunks));

	return chunk;
}

/* Forward decl — used by producer_release below. */
void page_pool_put(void *page);

/*
 * Hold a "producer" reference on the chunk currently assigned to a
 * thread pool. The buffering path itself is both a producer and a
 * consumer of pool pages during Phase 2: the P3 receiver allocates
 * pages via page_pool_get_pages, then clone_page_buffer_add_batch can
 * release ("put back") those pages when the new batch overlaps an
 * existing entry (overwrite / merge), and the UFFD REMOVE-event
 * handler releases pages when the target munmap'd a range.
 *
 * With nothing holding a net reference on a producer's current chunk,
 * the sequence "alloc → add_batch overwrite → put back everything"
 * can take refcount to 0 and munmap the chunk while the producer's
 * pool->current_chunk still points at it. The next
 * page_pool_get_pages on that thread-pool then dereferences a freed
 * mapping and SIGSEGVs.
 *
 * We add one reference when we install a chunk as current_chunk and
 * drop it when we replace it (via page_pool_swap_current_chunk).
 * Net effect on consumers is zero.
 */
static void page_pool_producer_hold(void *chunk)
{
	struct chunk_header *hdr = (struct chunk_header *)chunk;
	atomic_fetch_add(&hdr->refcount, 1);
}

static void page_pool_producer_release(void *chunk)
{
	void *page;
	if (!chunk)
		return;
	/*
	 * Release via page_pool_put so if the producer held the last
	 * reference the normal tracking+munmap path runs. The "page"
	 * we pass is the chunk header page itself — same chunk base.
	 */
	page = chunk;
	page_pool_put(page);
}

/*
 * Replace pool->current_chunk with a freshly-allocated chunk. Takes
 * care of producer reference bookkeeping so the old chunk can be
 * safely munmap'd if the consumer has already drained all its pages.
 */
static void page_pool_swap_current_chunk(struct thread_pool *pool)
{
	void *old_chunk = pool->current_chunk;
	void *new_chunk = alloc_chunk();

	page_pool_producer_hold(new_chunk);
	pool->current_chunk = new_chunk;
	pool->next_page = 1;  /* Skip header page */
	page_pool_producer_release(old_chunk);
}

int page_pool_thread_init(int thread_id)
{
	BUG_ON(thread_id < 0 || thread_id >= CLONE_MAX_THREADS);

	if (pools[thread_id].initialized)
		return 0;

	/* First thread initializes the chunk list lock */
	if (!atomic_exchange(&global_init_done, true)) {
		pthread_spin_init(&chunk_list_lock, PTHREAD_PROCESS_PRIVATE);
		atomic_init(&nr_chunks, 0);
	}

	pools[thread_id].current_chunk = alloc_chunk();
	page_pool_producer_hold(pools[thread_id].current_chunk);
	pools[thread_id].next_page = 1;  /* Skip header page */
	pools[thread_id].initialized = true;

	pr_debug("Thread %d pool initialized\n", thread_id);
	return 0;
}

/*
 * Get exactly nr_pages contiguous pages for direct decompression.
 * Each page must be freed individually with page_pool_put().
 */
void *page_pool_get_pages(int thread_id, int nr_pages)
{
	struct thread_pool *pool;
	void *pages_start;

	BUG_ON(thread_id < 0 || thread_id >= CLONE_MAX_THREADS);
	BUG_ON(nr_pages <= 0 || (unsigned int)nr_pages > CLONE_PAGES_PER_CHUNK - 1);

	pool = &pools[thread_id];

	BUG_ON(!pool->initialized);

	/* Need new chunk if not enough pages left */
	if (pool->next_page + (unsigned int)nr_pages > CLONE_PAGES_PER_CHUNK)
		page_pool_swap_current_chunk(pool);

	/* Allocate exactly nr_pages contiguous pages */
	pages_start = (char *)pool->current_chunk + (pool->next_page * PAGE_SIZE);
	pool->next_page += nr_pages;

	/* Update refcount and max_allocated */
	{
		struct chunk_header *hdr = (struct chunk_header *)pool->current_chunk;
		int current_alloc = pool->next_page;
		int old_max;

		atomic_fetch_add(&hdr->refcount, nr_pages);

		do {
			old_max = atomic_load(&hdr->max_allocated);
			if (current_alloc <= old_max)
				break;
		} while (!atomic_compare_exchange_weak(&hdr->max_allocated, &old_max, current_alloc));
	}

	atomic_fetch_add(&total_alloc_count, nr_pages);

	return pages_start;
}

void page_pool_put(void *page)
{
	struct chunk_header *hdr;
	int old_ref;

	if (!page)
		return;

	/* Mask page address to chunk base (chunks are CLONE_CHUNK_ALIGN aligned). */
	hdr = (struct chunk_header *)((unsigned long)page & CLONE_CHUNK_ALIGN_MASK);

	/* Validate - check self-pointer */
	if (hdr->base != hdr) {
		pr_err("BUG: page_pool_put called with invalid page %p\n", page);
		BUG();
	}

	old_ref = atomic_fetch_sub(&hdr->refcount, 1);

	if (old_ref <= 0) {
		pr_err("BUG: page_pool_put refcount already %d for page %p "
		       "chunk=%p[%d] — double free!\n",
		       old_ref, page, hdr, hdr->chunk_idx);
		BUG();
	}

	/* Track put count */
	{
		unsigned long put_cnt = atomic_fetch_add(&total_put_count, 1) + 1;
		if (put_cnt % CLONE_LOG_SAMPLE_1M == 0) {
			pr_debug("PAGE_POOL_PUT: total=%lu chunk=%p[%d] refcount_was=%d\n",
			       put_cnt, hdr, hdr->chunk_idx, old_ref);
		}
	}

	/* Last reference? munmap the entire chunk */
	if (old_ref == 1) {
		int chunk_idx = hdr->chunk_idx;
		int freed_count = atomic_fetch_add(&total_chunks_freed, 1) + 1;

		(void)freed_count; /* used by pr_debug when logging enabled */
		pr_debug("PAGE_POOL_FREE: chunk=%p[%d] total_freed=%d\n",
		       hdr, chunk_idx, freed_count);

		/* Remove from tracking list - chunk must be tracked */
		pthread_spin_lock(&chunk_list_lock);
		BUG_ON(chunk_idx < 0 || chunk_idx >= CLONE_MAX_POOL_CHUNKS);
		BUG_ON(all_chunks[chunk_idx] != hdr);
		all_chunks[chunk_idx] = NULL;
		pthread_spin_unlock(&chunk_list_lock);

		madvise(hdr, CLONE_CHUNK_SIZE, MADV_DONTNEED);
	}
}

/* Print chunk stats */
void page_pool_dump_stats(void)
{
	int i, n;
	int min_ref = INT_MAX, max_ref = 0;
	int null_slots = 0, active = 0;
	unsigned long total_outstanding = 0;

	if (!atomic_load(&global_init_done))
		return;

	pthread_spin_lock(&chunk_list_lock);
	n = atomic_load(&nr_chunks);
	for (i = 0; i < n; i++) {
		if (all_chunks[i]) {
			struct chunk_header *hdr = all_chunks[i];
			int ref = atomic_load(&hdr->refcount);
			active++;
			total_outstanding += ref;
			if (ref < min_ref) min_ref = ref;
			if (ref > max_ref) max_ref = ref;
		} else {
			null_slots++;
		}
	}
	pthread_spin_unlock(&chunk_list_lock);

	pr_debug("PAGE_POOL: chunks=%d active=%d freed=%d | outstanding=%lu | "
	       "alloc=%lu put=%lu diff=%lu | ref_range=[%d,%d]\n",
	       n, active, atomic_load(&total_chunks_freed), total_outstanding,
	       atomic_load(&total_alloc_count), atomic_load(&total_put_count),
	       atomic_load(&total_alloc_count) - atomic_load(&total_put_count),
	       min_ref == INT_MAX ? 0 : min_ref, max_ref);
}

/* Show chunk utilization */
void page_pool_dump_utilization(void)
{
	int i, n;
	unsigned long total_allocated = 0, total_capacity = 0;
	int capacity = CLONE_PAGES_PER_CHUNK - 1;

	if (!atomic_load(&global_init_done))
		return;

	pthread_spin_lock(&chunk_list_lock);
	n = atomic_load(&nr_chunks);
	for (i = 0; i < n; i++) {
		if (all_chunks[i]) {
			struct chunk_header *hdr = all_chunks[i];
			total_allocated += atomic_load(&hdr->max_allocated);
			total_capacity += capacity;
		}
	}
	pthread_spin_unlock(&chunk_list_lock);

	pr_debug("PAGE_POOL_UTIL: allocated=%lu capacity=%lu (%.1f%%)\n",
	       total_allocated, total_capacity,
	       total_capacity > 0 ? (float)total_allocated / total_capacity * 100 : 0);
}

void page_pool_mark_drain_started(void)
{
	pr_debug("PAGE_POOL: Drain started, alloc=%lu put=%lu\n",
	       atomic_load(&total_alloc_count), atomic_load(&total_put_count));
}

/*
 * Get chunk ID from a page data pointer.
 * Returns chunk index (0 to nr_chunks-1) or -1 if not found.
 * Used by drain to group pages by chunk for ordered freeing.
 */
int page_pool_get_chunk_id(void *page)
{
	struct chunk_header *hdr;
	int i, n;

	if (!page || !atomic_load(&global_init_done))
		return -1;

	/* Calculate chunk base from page address */
	hdr = (struct chunk_header *)((unsigned long)page & CLONE_CHUNK_ALIGN_MASK);

	/* Validate self-pointer */
	if (hdr->base != hdr)
		return -1;

	/* Find chunk index in tracking array */
	pthread_spin_lock(&chunk_list_lock);
	n = atomic_load(&nr_chunks);
	for (i = 0; i < n; i++) {
		if (all_chunks[i] == hdr) {
			pthread_spin_unlock(&chunk_list_lock);
			return i;
		}
	}
	pthread_spin_unlock(&chunk_list_lock);

	return -1;
}

/* Get current number of allocated chunks */
int page_pool_get_nr_chunks(void)
{
	if (!atomic_load(&global_init_done))
		return 0;
	return atomic_load(&nr_chunks);
}

