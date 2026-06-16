/*
 * CLONE userfaultfd handling on the target (restore) side.
 *
 * Owns the page buffer that holds pages received in Phase 2, the drain
 * threads that apply buffered pages via UFFDIO_COPY, and the page-fault
 * handlers that serve in-flight faults from the buffer (or fetch on
 * demand). Coordinates the all-pages-sent / drain-complete / restore-done
 * handshake with the source.
 */

#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/userfaultfd.h>

#include "int.h"
#include "page.h"
#include "clone/clone-uffd.h"
#include "clone/clone-bulk-send.h"
#include "clone/clone-bulk-recv.h"
#include "uffd.h"
#include "uffd-internal.h"
#include "page-xfer.h"
#include "criu-log.h"
#include "xmalloc.h"
#include "common/list.h"
#include "common/bug.h"
#include "clone/pf-tracker.h"
#include "clone/page-pool.h"
#include "clone/clone-batch-bitmap.h"
#include "clone/unmapped-tracker.h"
#include "clone/page-state-tracker.h"
#include "pstree.h"
#include "rst_info.h"

#undef LOG_PREFIX
#define LOG_PREFIX "clone-uffd: "

/*
 * Main thread reuses P3 thread 0's pool for Phase 4 dirty pages.
 * P3 receivers are stopped by Phase 4, so no contention.
 */
#define PHASE4_POOL_ID 0

/*
 * 256KB-aligned batch buffer entry.
 * Each entry holds up to CLONE_BATCH_PAGES (64) contiguous pages.
 * A bitmap tracks which pages within the batch are valid.
 * Drain can issue a single UFFDIO_COPY for the entire batch.
 */
#define BATCH_ENTRY_MAGIC	0xBA7C4E71  /* "BATCH_ENTRY" alive */
#define BATCH_ENTRY_DEAD	0xDEADBEEF  /* freed */

struct batch_buffer_entry {
	unsigned int magic;		/* BATCH_ENTRY_MAGIC or BATCH_ENTRY_DEAD */
	unsigned long base_vaddr;	/* 256KB-aligned start address */
	void *data;			/* Contiguous page pool allocation */
	clone_batch_bitmap_t page_bitmap;	/* 1 = page present, 0 = absent */
	clone_batch_bitmap_t initial_bitmap; /* Bits ever set (for drain free accounting) */
	int nr_pages;			/* popcount(page_bitmap) */
	struct hlist_node hash;
	struct list_head chunk_list;	/* Link in chunk's list for ordered drain */
	int chunk_id;			/* Cached page-pool chunk ID */
};

static struct {
	struct hlist_head *hash_table;
	unsigned long nr_pages;		/* Total individual pages buffered */
	unsigned long nr_applied;
	unsigned long nr_discarded;
	unsigned long nr_eagain;
	bool initialized;
} clone_buffer = { .initialized = false };

/*
 * Chunk-ordered drain index.
 * Allows draining batches grouped by their page pool chunk, so chunks
 * can be freed progressively instead of all at the end.
 */
struct chunk_drain_entry {
	struct list_head batches;	/* List of batch_buffer_entry in this chunk */
	pthread_spinlock_t lock;	/* Per-chunk lock for drain */
	atomic_int batch_count;		/* Number of batches in this chunk's list */
};

static struct chunk_drain_entry chunk_index[CLONE_MAX_POOL_CHUNKS];
static atomic_bool chunk_index_initialized = false;
static atomic_int nr_active_chunks = 0;

/* Fine-grained locks for batch buffer */
static pthread_spinlock_t hash_locks[CLONE_BATCH_NUM_HASH_LOCKS];


static inline int lock_index(unsigned int hash)
{
	return hash / CLONE_BATCH_BUCKETS_PER_LOCK;
}

/*
 * Multithreaded drain configuration.
 * Each thread handles a range of chunks for parallel draining.
 * Drain thread count is runtime-configurable via --clone-drain-threads.
 */

struct drain_thread_args {
	int thread_id;
};

static pthread_t drain_threads[CLONE_MAX_DRAIN_THREADS];
static struct drain_thread_args drain_args[CLONE_MAX_DRAIN_THREADS];
static atomic_bool drain_thread_stop = false;
static atomic_int drain_threads_active = 0;
static struct list_head *drain_lpis = NULL;  /* lpis list for EAGAIN handling */
static atomic_ulong total_drained = 0;  /* Total pages drained across all threads */
static atomic_int next_drain_chunk = 0;  /* Work-stealing: next chunk to process */
static int max_drain_chunks = 0;  /* Total chunks to drain */
static struct timespec drain_start_time;  /* For TIMING prefix debug */


static inline unsigned int batch_buffer_hash(unsigned long vaddr)
{
	return (vaddr >> CLONE_BATCH_SHIFT) & (CLONE_BATCH_BUFFER_HASH_SIZE - 1);
}

static inline unsigned long batch_align(unsigned long vaddr)
{
	return vaddr & CLONE_BATCH_ALIGN_MASK;
}

static inline int batch_page_index(unsigned long vaddr)
{
	return (vaddr >> PAGE_SHIFT) & (CLONE_BATCH_PAGES - 1);
}

/*
 * Result codes for clone_uffd_copy_pages()
 */
enum clone_copy_result {
	CLONE_COPY_OK = 0,
	CLONE_COPY_EAGAIN = 1,
	CLONE_COPY_EEXIST = 2,
	CLONE_COPY_ENOENT = 3,
	CLONE_COPY_ERROR = -1,
};

/*
 * Unified UFFDIO_COPY wrapper for CLONE mode.
 * Performs the ioctl and handles soft errors uniformly.
 *
 * @uffd: userfaultfd file descriptor
 * @dst: destination address in target process
 * @src: source buffer
 * @nr_pages: number of pages to copy
 * @copied_out: if non-NULL, set to number of pages actually copied on success
 *
 * Returns: CLONE_COPY_OK on success, or appropriate error code
 */
static enum clone_copy_result clone_uffd_copy_pages(int uffd, unsigned long dst,
						void *src, unsigned long nr_pages,
						unsigned long *copied_out)
{
	struct uffdio_copy uffd_copy = {
		.dst = dst,
		.src = (unsigned long)src,
		.len = nr_pages * PAGE_SIZE,
		.mode = 0,
		.copy = 0,
	};

	if (ioctl(uffd, UFFDIO_COPY, &uffd_copy) < 0) {
		switch (errno) {
		case EAGAIN:
			return CLONE_COPY_EAGAIN;
		case EEXIST:
			return CLONE_COPY_EEXIST;
		case ENOENT:
			return CLONE_COPY_ENOENT;
		default:
			return CLONE_COPY_ERROR;
		}
	}

	/* Check for soft error (error returned in .copy field) */
	if (uffd_copy.copy < 0) {
		errno = -uffd_copy.copy;
		switch (errno) {
		case EAGAIN:
			return CLONE_COPY_EAGAIN;
		case EEXIST:
			return CLONE_COPY_EEXIST;
		case ENOENT:
			return CLONE_COPY_ENOENT;
		default:
			return CLONE_COPY_ERROR;
		}
	}

	if (copied_out)
		*copied_out = uffd_copy.copy / PAGE_SIZE;

	return CLONE_COPY_OK;
}

/* CLONE_TRACK_* flags are defined in clone-uffd.h */

/*
 * Unified UFFDIO_COPY with full tracking.
 * Handles buffer stats, page state, unmapped tracker, and EAGAIN queue.
 *
 * @uffd: userfaultfd file descriptor
 * @vaddr: destination virtual address
 * @data: source data buffer
 * @nr_pages: number of pages to copy
 * @lpi: lazy_pages_info (NULL for drain mode)
 * @lpis: list of lpis for drain EAGAIN queue (NULL if lpi provided)
 * @flags: CLONE_TRACK_* flags
 * @caller: caller name for debug messages
 *
 * Returns:
 *   1 - success (page copied)
 *   0 - soft handled (ENOENT unmapped, EAGAIN queued, EEXIST already done)
 *  -1 - error
 *  -EAGAIN - kernel busy (only with CLONE_TRACK_RETRY flag)
 */
int clone_uffd_copy(int uffd, unsigned long vaddr, void *data,
		  unsigned long nr_pages,
		  struct lazy_pages_info *lpi,
		  struct list_head *lpis,
		  unsigned int flags,
		  const char *caller)
{
	enum clone_copy_result res;
	unsigned long copied = 0;

	res = clone_uffd_copy_pages(uffd, vaddr, data, nr_pages, &copied);

	switch (res) {
	case CLONE_COPY_OK: {
		unsigned long i;

		/*
		 * UFFDIO_COPY may install FEWER than nr_pages (short copy):
		 * the kernel returns success with uffd_copy.copy < len (e.g. it
		 * hit an already-present page mid-range). Only the first
		 * `copied` pages actually have data — mark exactly those COPIED,
		 * then re-issue for the uncopied remainder so it is not silently
		 * left missing (SIGBUS/zero on restore).
		 */
		if (copied == 0)
			copied = nr_pages; /* defensive: shouldn't happen on OK */

		if (!(flags & CLONE_TRACK_RETRY))
			__sync_fetch_and_add(&clone_buffer.nr_applied, 1);
		pf_tracker_set_state(vaddr, PF_STATE_COMPLETED);
		for (i = 0; i < copied; i++)
			page_state_set(vaddr + i * PAGE_SIZE, PAGE_STATE_COPIED);
		if (lpi)
			lpi->copied_pages += copied;

		if (copied < nr_pages) {
			/* Handle the uncopied tail with the same tracking. */
			return clone_uffd_copy(uffd, vaddr + copied * PAGE_SIZE,
					       (char *)data + copied * PAGE_SIZE,
					       nr_pages - copied, lpi, lpis,
					       flags, caller);
		}
		return 1;
	}

	case CLONE_COPY_EEXIST: {
		unsigned long i;

		if (!(flags & CLONE_TRACK_RETRY))
			__sync_fetch_and_add(&clone_buffer.nr_discarded, 1);
		for (i = 0; i < nr_pages; i++) {
			unsigned long addr = vaddr + i * PAGE_SIZE;

			if (!unmapped_tracker_is_unmapped(addr) &&
			    page_state_get(addr) != PAGE_STATE_DIRTY)
				page_state_set(addr, PAGE_STATE_DISCARDED);
		}
		if (flags & CLONE_TRACK_STRICT) {
			pr_err("BUG: %s EEXIST at 0x%lx - duplicate copy!\n", caller, vaddr);
			page_state_print_history(vaddr);
			BUG();
		}
		return 0;  /* soft handled - drain already did it */
	}

	case CLONE_COPY_ENOENT: {
		unsigned long i;

		if (!(flags & CLONE_TRACK_RETRY))
			__sync_fetch_and_add(&clone_buffer.nr_discarded, 1);
		if (!unmapped_tracker_is_unmapped(vaddr)) {
			for (i = 0; i < nr_pages; i++)
				page_state_set(vaddr + i * PAGE_SIZE, PAGE_STATE_DISCARDED);
			unmapped_tracker_mark_range(vaddr, nr_pages * PAGE_SIZE);
		}
		return 0;
	}

	case CLONE_COPY_EAGAIN:
		if (flags & CLONE_TRACK_RETRY)
			return -EAGAIN;
		__sync_fetch_and_add(&clone_buffer.nr_eagain, 1);
		pr_debug("%s EAGAIN at 0x%lx nr_pages=%lu\n",
		       caller, vaddr, nr_pages);
		if (lpis) {
			/* Drain mode - queue copies data, caller frees original */
			clone_queue_drain_eagain_request(lpis, vaddr, data);
		} else if (lpi) {
			/* Normal mode - queue copies data */
			pf_tracker_set_state(vaddr, PF_STATE_PENDING_EAGAIN);
			clone_queue_eagain_request(lpi, vaddr, nr_pages, data, caller);
		}
		return 0;

	case CLONE_COPY_ERROR:
		pr_err("%s: 0x%lx FAILED errno=%d\n", caller, vaddr, errno);
		page_state_print_history(vaddr);
		BUG();
	}

	return -1;  /* unreachable */
}

int clone_page_buffer_init(void)
{
	int i;

	if (clone_buffer.initialized)
		return 0;

	clone_buffer.hash_table = xmalloc(CLONE_BATCH_BUFFER_HASH_SIZE *
					sizeof(struct hlist_head));
	BUG_ON(!clone_buffer.hash_table);

	for (i = 0; i < CLONE_BATCH_BUFFER_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&clone_buffer.hash_table[i]);

	for (i = 0; i < CLONE_BATCH_NUM_HASH_LOCKS; i++)
		pthread_spin_init(&hash_locks[i], PTHREAD_PROCESS_PRIVATE);

	/* Initialize chunk drain index */
	for (i = 0; i < CLONE_MAX_POOL_CHUNKS; i++) {
		INIT_LIST_HEAD(&chunk_index[i].batches);
		pthread_spin_init(&chunk_index[i].lock, PTHREAD_PROCESS_PRIVATE);
		atomic_init(&chunk_index[i].batch_count, 0);
	}
	atomic_store(&chunk_index_initialized, true);

	clone_buffer.nr_pages = 0;
	clone_buffer.nr_applied = 0;
	clone_buffer.nr_discarded = 0;
	clone_buffer.nr_eagain = 0;
	clone_buffer.initialized = true;

	pr_info("CLONE batch buffer initialized (buckets=%d, locks=%d, chunk_slots=%d)\n",
		CLONE_BATCH_BUFFER_HASH_SIZE, CLONE_BATCH_NUM_HASH_LOCKS, CLONE_MAX_POOL_CHUNKS);
	return 0;
}

int clone_page_buffer_thread_init(int thread_id)
{
	return page_pool_thread_init(thread_id);
}

/*
 * Add a contiguous run of pages to the buffer at a given offset within
 * a 256KB-aligned batch.
 *
 * @base_vaddr: 256KB-aligned start address of the batch
 * @data: page data at data + page_offset * PAGE_SIZE
 * @nr_pages: number of valid pages (1..CLONE_BATCH_PAGES)
 * @page_offset: index of first valid page within the batch (0..63)
 * @thread_id: pool thread id (used only when creating new entry from temp data)
 * @owns_data: true = data is a CLONE_BATCH_PAGES pool allocation, ownership
 *             transferred. false = data is a temp buffer, only read from it.
 *
 * Bitmap bits [page_offset .. page_offset+nr_pages) are set.
 */
int clone_page_buffer_add_batch(unsigned long base_vaddr, void *data,
			      int nr_pages, int page_offset,
			      int thread_id, bool owns_data)
{
	struct batch_buffer_entry *entry;
	unsigned int hash;
	int lock_idx;
	clone_batch_bitmap_t new_bitmap;
	int i;

	BUG_ON(!clone_buffer.initialized);
	BUG_ON(base_vaddr != batch_align(base_vaddr));
	BUG_ON(nr_pages <= 0 || nr_pages > CLONE_BATCH_PAGES);
	if (page_offset < 0 || page_offset + nr_pages > CLONE_BATCH_PAGES) {
		pr_err("BUG: add_batch overflow: base=0x%lx offset=%d nr_pages=%d sum=%d max=%d\n",
		       base_vaddr, page_offset, nr_pages, page_offset + nr_pages, CLONE_BATCH_PAGES);
		BUG();
	}

	clone_batch_bitmap_zero(&new_bitmap);
	clone_batch_bitmap_set_range(&new_bitmap, page_offset, nr_pages);

	hash = batch_buffer_hash(base_vaddr);
	lock_idx = lock_index(hash);

	pthread_spin_lock(&hash_locks[lock_idx]);

	/* Check if batch entry already exists (dirty re-send) */
	hlist_for_each_entry(entry, &clone_buffer.hash_table[hash], hash) {
		if (entry->base_vaddr == base_vaddr) {
			/* Overwrite pages in existing batch */
			for (i = 0; i < nr_pages; i++) {
				int idx = page_offset + i;

				memcpy((char *)entry->data + idx * PAGE_SIZE,
				       (char *)data + idx * PAGE_SIZE, PAGE_SIZE);

				if (!clone_batch_bitmap_test(&entry->page_bitmap, idx)) {
					clone_batch_bitmap_set(&entry->page_bitmap, idx);
					clone_batch_bitmap_set(&entry->initial_bitmap, idx);
					entry->nr_pages++;
					__sync_fetch_and_add(&clone_buffer.nr_pages, 1);
				}
				page_state_set_with_crc(base_vaddr + idx * PAGE_SIZE,
							PAGE_STATE_IN_BUFFER,
							(char *)entry->data + idx * PAGE_SIZE);
			}
			pthread_spin_unlock(&hash_locks[lock_idx]);

			/* Free incoming pool buffer if caller passed ownership */
			if (owns_data) {
				for (i = 0; i < CLONE_BATCH_PAGES; i++)
					page_pool_put((char *)data + i * PAGE_SIZE);
			}
			return 0;
		}
	}

	/* New entry */
	{
		void *batch_data;

		if (owns_data) {
			/* Take ownership of caller's pool buffer (zero copy) */
			batch_data = data;
		} else {
			/* Allocate pool buffer and copy from temp data */
			batch_data = page_pool_get_pages(thread_id, CLONE_BATCH_PAGES);
			BUG_ON(!batch_data);
			memcpy((char *)batch_data + page_offset * PAGE_SIZE,
			       (char *)data + page_offset * PAGE_SIZE,
			       nr_pages * PAGE_SIZE);
		}

	entry = xmalloc(sizeof(*entry));
	BUG_ON(!entry);

	entry->magic = BATCH_ENTRY_MAGIC;
	entry->base_vaddr = base_vaddr;
	entry->data = batch_data;
	clone_batch_bitmap_copy(&entry->page_bitmap, &new_bitmap);
	clone_batch_bitmap_copy(&entry->initial_bitmap, &new_bitmap);
	entry->nr_pages = nr_pages;
	INIT_HLIST_NODE(&entry->hash);
	INIT_LIST_HEAD(&entry->chunk_list);
	entry->chunk_id = page_pool_get_chunk_id(batch_data);

	/*
	 * Publish the entry to both indices under the hash lock so a concurrent
	 * lookup_and_remove can never observe it in the hash before it exists
	 * in the chunk list. Lock order: hash_lock -> chunk_index.lock (matches
	 * lookup_and_remove and remove_range).
	 */
	if (entry->chunk_id >= 0 && entry->chunk_id < CLONE_MAX_POOL_CHUNKS) {
		pthread_spin_lock(&chunk_index[entry->chunk_id].lock);
		list_add_tail(&entry->chunk_list, &chunk_index[entry->chunk_id].batches);
		atomic_fetch_add(&chunk_index[entry->chunk_id].batch_count, 1);
		pthread_spin_unlock(&chunk_index[entry->chunk_id].lock);
	}

	hlist_add_head(&entry->hash, &clone_buffer.hash_table[hash]);

	for (i = 0; i < nr_pages; i++)
		page_state_set_with_crc(base_vaddr + (page_offset + i) * PAGE_SIZE,
					PAGE_STATE_IN_BUFFER,
					(char *)batch_data + (page_offset + i) * PAGE_SIZE);
	pthread_spin_unlock(&hash_locks[lock_idx]);
	} /* end new entry block */

	if (entry->chunk_id >= 0 && entry->chunk_id < CLONE_MAX_POOL_CHUNKS) {
		int cur_max = atomic_load(&nr_active_chunks);

		while (entry->chunk_id >= cur_max) {
			if (atomic_compare_exchange_weak(&nr_active_chunks, &cur_max, entry->chunk_id + 1))
				break;
		}
	}

	__sync_fetch_and_add(&clone_buffer.nr_pages, nr_pages);
	return 0;
}

/*
 * Get the data pointer for an existing batch entry.
 * Returns entry->data if an entry exists for this 256KB-aligned base,
 * NULL otherwise. Caller can decompress directly into the returned pointer.
 *
 * LOCKING: On success the hash lock is held on return and must be released
 * by a matching call to clone_page_buffer_mark_pages(). This keeps the entry
 * and its data buffer stable across the caller's decompress/memcpy so
 * concurrent producers cannot clobber bytes mid-write.
 */
void *clone_page_buffer_get_data_ptr(unsigned long base_vaddr,
				   int page_offset, int nr_pages)
{
	struct batch_buffer_entry *entry;
	unsigned int hash;
	int lock_idx;

	if (!clone_buffer.initialized)
		return NULL;

	BUG_ON(base_vaddr != batch_align(base_vaddr));

	hash = batch_buffer_hash(base_vaddr);
	lock_idx = lock_index(hash);

	pthread_spin_lock(&hash_locks[lock_idx]);
	hlist_for_each_entry(entry, &clone_buffer.hash_table[hash], hash) {
		if (entry->base_vaddr == base_vaddr)
			return entry->data;  /* lock held — released by mark_pages */
	}
	pthread_spin_unlock(&hash_locks[lock_idx]);

	return NULL;
}

/*
 * Mark pages as valid in an existing batch after direct decompress.
 * Called after decompressing directly into entry->data.
 *
 * LOCKING: The hash lock is expected to be held by a prior successful
 * clone_page_buffer_get_data_ptr() on the same base_vaddr. This function
 * releases that lock before returning.
 */
void clone_page_buffer_mark_pages(unsigned long base_vaddr,
				int page_offset, int nr_pages)
{
	struct batch_buffer_entry *entry;
	unsigned int hash;
	int lock_idx;
	int i;

	hash = batch_buffer_hash(base_vaddr);
	lock_idx = lock_index(hash);

	hlist_for_each_entry(entry, &clone_buffer.hash_table[hash], hash) {
		if (entry->base_vaddr == base_vaddr) {
			for (i = 0; i < nr_pages; i++) {
				int idx = page_offset + i;

				if (!clone_batch_bitmap_test(&entry->page_bitmap, idx)) {
					clone_batch_bitmap_set(&entry->page_bitmap, idx);
					clone_batch_bitmap_set(&entry->initial_bitmap, idx);
					entry->nr_pages++;
					__sync_fetch_and_add(&clone_buffer.nr_pages, 1);
				}
				page_state_set_with_crc(base_vaddr + idx * PAGE_SIZE,
							PAGE_STATE_IN_BUFFER,
							(char *)entry->data + idx * PAGE_SIZE);
			}
			pthread_spin_unlock(&hash_locks[lock_idx]);
			return;
		}
	}
	pthread_spin_unlock(&hash_locks[lock_idx]);

	pr_err("BUG: mark_pages called for non-existing entry base=0x%lx\n", base_vaddr);
	BUG();
}

/*
 * Tear down an emptied batch entry.
 *
 * Unlinks the entry from both indices it lives in (the hash table and its
 * per-chunk drain list), returns the pool pages selected by @free_bm to the
 * pool, poisons the entry and frees it.
 *
 * Contract: caller holds hash_locks[@lock_idx] and has ALREADY decided the
 * batch is empty. This function performs the hlist_del and DROPS that lock
 * (matching the original inline order, which releases the hash lock before
 * taking the per-chunk lock). @free_bm is the set of slot indices to free;
 * each caller computes it differently (lookup_and_remove excludes the page
 * it hands back to its caller; remove_range includes the pages it discards).
 *
 * NOTE: this does not address the drain-vs-fault use-after-free race in the
 * window after the hash lock is dropped — it only factors out the shared
 * teardown; the locking is identical to the previous inline code.
 */
static void clone_batch_destroy_locked(struct batch_buffer_entry *entry,
				       int lock_idx,
				       const clone_batch_bitmap_t *free_bm)
{
	int chunk_id = entry->chunk_id;
	int j;

	hlist_del(&entry->hash);
	pthread_spin_unlock(&hash_locks[lock_idx]);

	if (chunk_id >= 0 && chunk_id < CLONE_MAX_POOL_CHUNKS) {
		pthread_spin_lock(&chunk_index[chunk_id].lock);
		list_del(&entry->chunk_list);
		atomic_fetch_sub(&chunk_index[chunk_id].batch_count, 1);
		pthread_spin_unlock(&chunk_index[chunk_id].lock);
	}

	CLONE_BATCH_BITMAP_FOR_EACH_SET(free_bm, j) {
		page_pool_put((char *)entry->data + j * PAGE_SIZE);
	}

	entry->magic = BATCH_ENTRY_DEAD;
	xfree(entry);
}

/*
 * Look up a single page in the batch buffer.
 * Returns a pointer to a PAGE_SIZE buffer that the caller must free
 * via page_pool_put(), or NULL if the page is not in the buffer.
 *
 * The page is cleared from the batch bitmap. If the batch becomes empty,
 * the entry is removed and its data buffer freed.
 */
void *clone_page_buffer_lookup_and_remove(unsigned long vaddr)
{
	struct batch_buffer_entry *entry;
	unsigned long base;
	unsigned int hash;
	int lock_idx, page_idx;
	void *page_ptr;

	if (!clone_buffer.initialized)
		return NULL;

	base = batch_align(vaddr);
	page_idx = batch_page_index(vaddr);
	hash = batch_buffer_hash(base);
	lock_idx = lock_index(hash);

	pthread_spin_lock(&hash_locks[lock_idx]);
	hlist_for_each_entry(entry, &clone_buffer.hash_table[hash], hash) {
		if (entry->magic != BATCH_ENTRY_MAGIC) {
			pr_err("lookup_and_remove found DEAD entry in hash! "
			       "vaddr=0x%lx base=0x%lx magic=0x%x\n",
			       vaddr, base, entry->magic);
			BUG();
		}
		if (entry->base_vaddr != base)
			continue;
		if (!clone_batch_bitmap_test(&entry->page_bitmap, page_idx)) {
			pthread_spin_unlock(&hash_locks[lock_idx]);
			return NULL;
		}

		page_ptr = (char *)entry->data + page_idx * PAGE_SIZE;

		/* Clear bit and decrement count */
		clone_batch_bitmap_clear(&entry->page_bitmap, page_idx);
		entry->nr_pages--;
		__sync_fetch_and_sub(&clone_buffer.nr_pages, 1);

		if (entry->nr_pages == 0) {
			/*
			 * Batch empty — free every slot we still own. page_bitmap
			 * is 0 here, so the owned set is just the unused slots
			 * (~initial_bitmap); exclude page_idx, which we hand back
			 * to the caller to free. clone_batch_destroy_locked()
			 * drops the hash lock.
			 */
			clone_batch_bitmap_t free_bm;

			clone_batch_bitmap_not(&free_bm, &entry->initial_bitmap);
			clone_batch_bitmap_mask(&free_bm, CLONE_BATCH_PAGES);
			clone_batch_bitmap_clear(&free_bm, page_idx);

			clone_batch_destroy_locked(entry, lock_idx, &free_bm);
			return page_ptr;
		}

		pthread_spin_unlock(&hash_locks[lock_idx]);
		return page_ptr;
	}
	pthread_spin_unlock(&hash_locks[lock_idx]);

	return NULL;
}

unsigned long clone_page_buffer_count(void)
{
	return clone_buffer.nr_pages;
}

/*
 * Remove all pages in a range from the buffer.
 * Called when VMA is unmapped - no point keeping these pages.
 * Operates at batch granularity: clears bitmap bits for affected pages.
 */
void clone_page_buffer_remove_range(unsigned long start, unsigned long len)
{
	struct batch_buffer_entry *entry;
	unsigned long base, end;
	unsigned long removed = 0;

	if (!clone_buffer.initialized)
		return;

	end = start + len;

	/* Iterate over 256KB-aligned batches that overlap the range */
	for (base = batch_align(start); base < end; base += CLONE_BATCH_SIZE) {
		unsigned int hash = batch_buffer_hash(base);
		int lock_idx = lock_index(hash);
		int first_page, last_page;
		clone_batch_bitmap_t clear_mask;
		clone_batch_bitmap_t masked;
		clone_batch_bitmap_t page_bitmap_pre_clear;
		int cleared;

		/* Which pages within this batch overlap [start, end)? */
		first_page = (base < start) ? batch_page_index(start) : 0;
		last_page = (base + CLONE_BATCH_SIZE > end)
			    ? batch_page_index(end - 1) : (CLONE_BATCH_PAGES - 1);

		/* Build mask of pages to clear */
		clone_batch_bitmap_zero(&clear_mask);
		clone_batch_bitmap_set_range(&clear_mask, first_page, last_page - first_page + 1);

		pthread_spin_lock(&hash_locks[lock_idx]);
		hlist_for_each_entry(entry, &clone_buffer.hash_table[hash], hash) {
			if (entry->base_vaddr != base)
				continue;

			clone_batch_bitmap_and(&masked, &entry->page_bitmap, &clear_mask);
			cleared = clone_batch_bitmap_popcount(&masked);
			if (cleared == 0) {
				pthread_spin_unlock(&hash_locks[lock_idx]);
				goto next_batch;
			}

			/*
			 * Snapshot the still-buffered pages BEFORE clearing the
			 * unmapped bits. The free mask below must include the
			 * pages we are about to discard (they are owned pool
			 * slots that nobody else will copy), so it has to be
			 * computed from the pre-clear bitmap — mirroring
			 * drain_apply_batch(). Computing it after clear_range
			 * leaks exactly the discarded pages.
			 */
			clone_batch_bitmap_copy(&page_bitmap_pre_clear, &entry->page_bitmap);

			clone_batch_bitmap_clear_range(&entry->page_bitmap, first_page,
						     last_page - first_page + 1);
			entry->nr_pages -= cleared;
			removed += cleared;

			if (entry->nr_pages == 0) {
				/*
				 * Batch empty — free unused slots (~initial_bitmap)
				 * plus the still-buffered pages we are discarding
				 * (page_bitmap_pre_clear, snapshotted before the
				 * clear above); page-fault-served slots are absent
				 * from both and stay freed. clone_batch_destroy_locked()
				 * drops the hash lock.
				 */
				clone_batch_bitmap_t free_bm;

				clone_batch_bitmap_not(&free_bm, &entry->initial_bitmap);
				clone_batch_bitmap_mask(&free_bm, CLONE_BATCH_PAGES);
				clone_batch_bitmap_or(&free_bm, &free_bm, &page_bitmap_pre_clear);

				clone_batch_destroy_locked(entry, lock_idx, &free_bm);
				goto next_batch;
			}

			pthread_spin_unlock(&hash_locks[lock_idx]);
			goto next_batch;
		}
		pthread_spin_unlock(&hash_locks[lock_idx]);
next_batch:;
	}

	if (removed > 0) {
		__sync_fetch_and_sub(&clone_buffer.nr_pages, removed);
		__sync_fetch_and_add(&clone_buffer.nr_discarded, removed);
		pr_debug("Removed %lu pages from buffer for UNMAP range 0x%lx-0x%lx\n",
			 removed, start, end);
	}
}


/*
 * Drain a batch via UFFDIO_COPY(s) and free its data.
 * Performs a single UFFDIO_COPY for full batches (bitmap == all-ones),
 * or falls back to per-page copies for partial batches.
 *
 * Returns number of pages drained.
 */
static unsigned long drain_apply_batch(struct batch_buffer_entry *entry,
				       struct list_head *lpis)
{
	unsigned long base = entry->base_vaddr;
	void *data = entry->data;
	unsigned long applied = 0;
	int uffd, i;

	if (entry->magic != BATCH_ENTRY_MAGIC) {
		pr_err("drain_apply_batch got DEAD entry! "
		       "base=0x%lx magic=0x%x data=%p\n",
		       base, entry->magic, data);
		BUG();
	}

	/* Fast path: full batch — single UFFDIO_COPY for 256KB */
	if (clone_batch_bitmap_is_full_upto(&entry->page_bitmap, CLONE_BATCH_PAGES)) {
		for (i = 0; i < CLONE_BATCH_PAGES; i++)
			page_state_set(base + i * PAGE_SIZE, PAGE_STATE_DRAIN_PENDING);

		uffd = clone_get_uffd_for_vaddr(lpis, base);
		if (uffd >= 0) {
			clone_uffd_copy(uffd, base, data, CLONE_BATCH_PAGES,
				      NULL, lpis, CLONE_TRACK_STRICT, "DRAIN_BATCH");
		}
		applied = CLONE_BATCH_PAGES;
	} else {
		/* Partial batch — per-page copies for set bits */
		CLONE_BATCH_BITMAP_FOR_EACH_SET(&entry->page_bitmap, i) {
			page_state_set(base + i * PAGE_SIZE, PAGE_STATE_DRAIN_PENDING);
			uffd = clone_get_uffd_for_vaddr(lpis, base + i * PAGE_SIZE);
			if (uffd >= 0) {
				clone_uffd_copy(uffd, base + i * PAGE_SIZE,
					      (char *)data + i * PAGE_SIZE, 1,
					      NULL, lpis, CLONE_TRACK_STRICT, "DRAIN");
			}
			applied++;
		}
	}

	/*
	 * Free pool pages. page_pool_get_pages(CLONE_BATCH_PAGES) set refcount.
	 * Page faults may have already freed some (cleared bitmap bits).
	 *
	 * free_bitmap = pages drain owns (bitmap) | unused slots (~initial_bitmap)
	 * Skip: pages served by page fault (initial_bitmap & ~bitmap) — already freed.
	 */
	{
		clone_batch_bitmap_t free_bitmap;
		clone_batch_bitmap_t pf_served_bm;
		int free_count, pf_served;

		clone_batch_bitmap_not(&free_bitmap, &entry->initial_bitmap);
		clone_batch_bitmap_mask(&free_bitmap, CLONE_BATCH_PAGES);
		clone_batch_bitmap_or(&free_bitmap, &free_bitmap, &entry->page_bitmap);
		free_count = clone_batch_bitmap_popcount(&free_bitmap);

		clone_batch_bitmap_not(&pf_served_bm, &entry->page_bitmap);
		clone_batch_bitmap_mask(&pf_served_bm, CLONE_BATCH_PAGES);
		clone_batch_bitmap_and(&pf_served_bm, &pf_served_bm, &entry->initial_bitmap);
		pf_served = clone_batch_bitmap_popcount(&pf_served_bm);

		if (pf_served > 0) {
			pr_debug("drain_apply_batch: base=0x%lx "
			       "pf_served=%d freeing=%d of %d\n",
			       base, pf_served, free_count, CLONE_BATCH_PAGES);
		}

		CLONE_BATCH_BITMAP_FOR_EACH_SET(&free_bitmap, i) {
			page_pool_put((char *)data + i * PAGE_SIZE);
		}
	}

	return applied;
}

/*
 * Background drain worker thread - proactively UFFDIO_COPY pages
 * from buffer to reduce future page faults and free memory.
 *
 * Each worker handles a subset of CHUNKS for chunk-ordered draining.
 * By draining all batches from one chunk before moving to the next,
 * chunks can be freed progressively instead of all at the end.
 */
static void *background_drain_worker(void *arg)
{
	struct drain_thread_args *args = (struct drain_thread_args *)arg;
	struct batch_buffer_entry *entry, *tmp_entry;
	unsigned long drained = 0;
	unsigned long last_progress_drained = 0;
	time_t last_progress_time = 0;
	int thread_id = args->thread_id;
	int chunk_id;
	int chunks_empty = 0;
	int chunks_with_batches = 0;
	char thread_name[16];

	snprintf(thread_name, sizeof(thread_name), "clone-drain-%d", thread_id);
	pthread_setname_np(pthread_self(), thread_name);

	pr_debug("Drain thread %d started, buffered=%lu pages\n", thread_id, clone_buffer.nr_pages);
	last_progress_time = time(NULL);

	while (!atomic_load(&drain_thread_stop) && clone_buffer.nr_pages > 0) {
		/* Work-stealing: atomically grab next chunk */
		chunk_id = atomic_fetch_add(&next_drain_chunk, 1);
		if (chunk_id >= max_drain_chunks)
			break;

		{
			unsigned long chunk_drained = 0;

			pthread_spin_lock(&chunk_index[chunk_id].lock);
			list_for_each_entry_safe(entry, tmp_entry,
						 &chunk_index[chunk_id].batches, chunk_list) {
				int nr = entry->nr_pages;

				/* Remove from chunk list while holding lock */
				list_del(&entry->chunk_list);
				atomic_fetch_sub(&chunk_index[chunk_id].batch_count, 1);
				pthread_spin_unlock(&chunk_index[chunk_id].lock);

				/* Remove from hash table before draining */
				{
					unsigned int hash = batch_buffer_hash(entry->base_vaddr);
					int lock_idx = lock_index(hash);

					pthread_spin_lock(&hash_locks[lock_idx]);
					hlist_del(&entry->hash);
					pthread_spin_unlock(&hash_locks[lock_idx]);
				}

				__sync_fetch_and_sub(&clone_buffer.nr_pages, nr);

				drained += drain_apply_batch(entry, drain_lpis);
				chunk_drained += nr;
				entry->magic = BATCH_ENTRY_DEAD;
				xfree(entry);

				/* Log progress every 100k pages or 10 seconds */
				if (drained - last_progress_drained >= CLONE_LOG_SAMPLE_1M ||
				    time(NULL) - last_progress_time >= CLONE_DRAIN_PROGRESS_SEC) {
					pr_debug("Drain thread %d: drained=%lu chunk=%d remaining=%lu\n",
					       thread_id, drained, chunk_id, clone_buffer.nr_pages);
					last_progress_drained = drained;
					last_progress_time = time(NULL);
				}

				pthread_spin_lock(&chunk_index[chunk_id].lock);
			}
			pthread_spin_unlock(&chunk_index[chunk_id].lock);

			if (chunk_drained == 0)
				chunks_empty++;
			else
				chunks_with_batches++;
		}
	}

	/* Update global statistics */
	atomic_fetch_add(&total_drained, drained);

	pr_debug("Drain thread %d finished: drained=%lu chunks_empty=%d chunks_with_batches=%d\n",
		 thread_id, drained, chunks_empty, chunks_with_batches);

	/* Decrement active thread count */
	if (atomic_fetch_sub(&drain_threads_active, 1) == 1) {
		struct timespec drain_end_time;
		unsigned long elapsed_ms;

		/*
		 * Last thread to exit. Add full memory barrier to ensure all
		 * UFFDIO_COPY writes are visible before signaling drain complete.
		 * This is critical on ARM where memory ordering is weaker.
		 */
		atomic_thread_fence(memory_order_seq_cst);

		/* Calculate and print drain duration */
		clock_gettime(CLOCK_MONOTONIC, &drain_end_time);
		elapsed_ms = (drain_end_time.tv_sec - drain_start_time.tv_sec) * 1000 +
			     (drain_end_time.tv_nsec - drain_start_time.tv_nsec) / 1000000;
		pr_debug("TIMING: drain took %lu ms\n", elapsed_ms);

		pr_info("Drain complete: total=%lu applied=%lu discarded=%lu eagain=%lu remaining=%lu\n",
		       atomic_load(&total_drained), clone_buffer.nr_applied,
		       clone_buffer.nr_discarded, clone_buffer.nr_eagain, clone_buffer.nr_pages);

		/* Print pool stats to check for leaks */
		page_pool_dump_stats();

		/* All pages should be drained - orphaned pages are a bug */
		BUG_ON(clone_buffer.nr_pages > 0);
	}

	return NULL;
}

int clone_start_drain_thread(struct list_head *lpis)
{
	int i;
	int chunks_per_thread;
	int total_chunks;
	int created = 0;

	if (atomic_load(&drain_threads_active) > 0)
		return 0;

	if (clone_buffer.nr_pages == 0)
		return 0;

	drain_lpis = lpis;  /* Store for EAGAIN handling */
	atomic_store(&drain_thread_stop, false);
	atomic_store(&total_drained, 0);

	/* Get number of chunks to drain */
	total_chunks = atomic_load(&nr_active_chunks);
	if (total_chunks == 0)
		total_chunks = page_pool_get_nr_chunks();
	if (total_chunks == 0)
		total_chunks = CLONE_MAX_POOL_CHUNKS;  /* Fallback: scan all slots */

	/* Divide chunks evenly among threads */
	chunks_per_thread = (total_chunks + clone_cfg.num_drain_threads - 1) / clone_cfg.num_drain_threads;
	if (chunks_per_thread < 1)
		chunks_per_thread = 1;

	/* Initialize work-stealing globals */
	atomic_store(&next_drain_chunk, 0);
	max_drain_chunks = total_chunks;

	for (i = 0; i < clone_cfg.num_drain_threads; i++) {
		drain_args[i].thread_id = i;

		BUG_ON(pthread_create(&drain_threads[i], NULL,
				      background_drain_worker, &drain_args[i]));
		atomic_fetch_add(&drain_threads_active, 1);
		created++;
	}

	/* Mark drain started and report any puts that happened before */
	page_pool_mark_drain_started();

	/* Record start time for TIMING debug */
	clock_gettime(CLOCK_MONOTONIC, &drain_start_time);

	pr_info("Started %d drain threads, buffered=%lu total_chunks=%d\n",
	       created, clone_buffer.nr_pages, total_chunks);

	return 0;
}

bool clone_drain_thread_running(void)
{
	return atomic_load(&drain_threads_active) > 0;
}

/*
 * Handle CLONE mode exit conditions.
 *
 * Exit sequence:
 * 1. Wait for all_pages_sent signal (guarantees all pages received from socket)
 * 2. Wait for drain thread to finish (buffer empty)
 * 3. Send ACK to source
 * 4. Cleanup and exit
 *
 * Returns:
 *   1  - should break the main loop (all done)
 *   0  - should continue the main loop
 */
int clone_handle_exit(struct list_head *lpis)
{
	struct lazy_pages_info *lpi, *n;

	/* Condition 1: Wait for all_pages_sent signal from source */
	if (!clone_is_all_pages_sent_received())
		return 0;

	/* Condition 2: Wait for drain thread to finish */
	if (clone_drain_thread_running())
		return 0;

	/* Condition 3: Wait for buffer to be empty */
	if (clone_page_buffer_count() > 0)
		return 0;

	/* Condition 4: Wait for EAGAIN requests to be processed */
	if (!clone_is_eagain_queue_empty())
		return 0;

	/* Cleanup all lpis */
	list_for_each_entry_safe(lpi, n, lpis, l) {
		lazy_pages_summary(lpi);
		list_del(&lpi->l);
		lpi_put(lpi);
	}

	return 1;  /* Exit main loop */
}

/*
 * EAGAIN Request Handling (CLONE mode)
 */

/* Pending EAGAIN requests list - protected by eagain_mutex */
static LIST_HEAD(eagain_requests);
static pthread_mutex_t eagain_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Queue an EAGAIN request for later retry in CLONE dump mode.
 * For copy operations, buf should point to the data to copy.
 * For zero operations, buf should be NULL.
 */
int clone_queue_eagain_request(struct lazy_pages_info *lpi, __u64 address,
			     unsigned long nr_pages, void *buf, const char *op_name)
{
	struct uffd_eagain_request *req;
	void *buf_copy = NULL;
	unsigned long len = nr_pages * page_size();

	/* Copy buffer if provided (copy operation) */
	if (buf) {
		buf_copy = xmalloc(len);
		BUG_ON(!buf_copy);
		memcpy(buf_copy, buf, len);
	}

	/* Create request entry */
	req = xmalloc(sizeof(*req));
	BUG_ON(!req);

	req->lpi = lpi;
	req->address = address;
	req->nr_pages = nr_pages;
	req->buf = buf_copy;  /* NULL for zero operations */
	INIT_LIST_HEAD(&req->l);

	pthread_mutex_lock(&eagain_mutex);
	list_add_tail(&req->l, &eagain_requests);
	pthread_mutex_unlock(&eagain_mutex);

	/* Only set page state after successfully queueing */
	page_state_set(address, PAGE_STATE_EAGAIN_QUEUED);

	pr_debug("queued 0x%llx nr_pages=%lu op=%s buf=%p buf_copy=%p\n",
	       address, nr_pages, op_name, buf, buf_copy);
	return 0;
}
/*
 * Find the lpi that owns a given vaddr.
 * Returns NULL if no matching lpi found (page unmapped or process exited).
 */
static struct lazy_pages_info *clone_find_lpi_for_vaddr(struct list_head *lpis,
						      unsigned long vaddr)
{
	struct lazy_pages_info *lpi;

	list_for_each_entry(lpi, lpis, l) {
		if (lpi->exited || lpi->lpfd.fd < 0)
			continue;
		if (clone_find_iov(lpi, vaddr))
			return lpi;
	}

	return NULL;
}

/*
 * Queue an EAGAIN request from drain thread context.
 * Finds the appropriate lpi for the vaddr and queues for retry.
 * Returns 0 on success (ownership of data transferred), -1 on error.
 */
int clone_queue_drain_eagain_request(struct list_head *lpis, unsigned long vaddr, void *data)
{
	struct lazy_pages_info *lpi = clone_find_lpi_for_vaddr(lpis, vaddr);

	if (lpi)
		return clone_queue_eagain_request(lpi, vaddr, 1, data, "drain");

	/* No matching lpi - this is a bug */
	pr_err("BUG: No lpi found for drain EAGAIN at 0x%lx\n", vaddr);
	page_state_print_history(vaddr);
	BUG();
	return -1;
}

/* Check if EAGAIN requests queue is empty */
bool clone_is_eagain_queue_empty(void)
{
	bool empty;

	pthread_mutex_lock(&eagain_mutex);
	empty = list_empty(&eagain_requests);
	pthread_mutex_unlock(&eagain_mutex);

	return empty;
}

/*
 * Retry a copy operation that previously failed with EAGAIN.
 * Returns: 0 on success, -EAGAIN if still blocked, -1 on error
 */
static int retry_uffd_copy(struct uffd_eagain_request *req)
{
	int ret;

	ret = clone_uffd_copy(req->lpi->lpfd.fd, req->address,
			    req->buf, req->nr_pages,
			    req->lpi, NULL,
			    CLONE_TRACK_RETRY | CLONE_TRACK_STRICT,
			    "EAGAIN_RETRY");
	if (ret == 1) {
		lp_debug(req->lpi, "EAGAIN copy retry succeeded for 0x%llx\n", req->address);
		return 0;
	}
	if (ret == -EAGAIN)
		return -EAGAIN;

	/* ENOENT or ERROR - unified handler already set page state */
	lp_err(req->lpi, "EAGAIN copy retry failed for 0x%llx\n", req->address);
	return -1;
}

/*
 * Retry a zero operation that previously failed with EAGAIN.
 * Returns: 0 on success, -EAGAIN if still blocked, -1 on error
 */
static int retry_uffd_zero(struct uffd_eagain_request *req)
{
	struct uffdio_zeropage uffdio_zeropage;

	uffdio_zeropage.range.start = req->address;
	uffdio_zeropage.range.len = req->nr_pages * page_size();
	uffdio_zeropage.mode = 0;
	uffdio_zeropage.zeropage = 0;

	if (ioctl(req->lpi->lpfd.fd, UFFDIO_ZEROPAGE, &uffdio_zeropage) == -1) {
		if (errno == EAGAIN)
			return -EAGAIN;

		if (errno == EEXIST) {
			pr_err("BUG: EAGAIN zero retry EEXIST at 0x%llx - duplicate zero!\n",
			       req->address);
			page_state_print_history(req->address);
			BUG();
		}

		lp_err(req->lpi, "EAGAIN zero retry failed for 0x%llx: %d\n",
		       req->address, errno);
		page_state_set(req->address, PAGE_STATE_DISCARDED);
		return -1;
	}

	/* Check for soft error */
	if (uffdio_zeropage.zeropage < 0) {
		errno = -uffdio_zeropage.zeropage;
		if (errno == EAGAIN)
			return -EAGAIN;

		lp_err(req->lpi, "EAGAIN zero retry soft error for 0x%llx: %d\n",
		       req->address, errno);
		page_state_set(req->address, PAGE_STATE_DISCARDED);
		return -1;
	}

	/* Success */
	pf_tracker_set_state(req->address, PF_STATE_COMPLETED);
	page_state_set(req->address, PAGE_STATE_COPIED);
	lp_debug(req->lpi, "EAGAIN zero retry succeeded for 0x%llx\n", req->address);
	return 0;
}

/*
 * Process pending EAGAIN requests.
 * Attempts to retry UFFDIO_COPY or UFFDIO_ZEROPAGE for requests that previously failed with EAGAIN.
 */
int clone_process_eagain_requests(void)
{
	struct uffd_eagain_request *req, *n;
	int ret;

	pthread_mutex_lock(&eagain_mutex);
	list_for_each_entry_safe(req, n, &eagain_requests, l) {
		/* Skip if process has exited */
		if (req->lpi->exited) {
			pr_warn("EAGAIN retry skipped, lpi unmapped for 0x%llx (op=%s)\n",
				 req->address, req->buf ? "copy" : "zero");
			page_state_set(req->address, PAGE_STATE_DISCARDED);
			list_del(&req->l);
			if (req->buf)
				xfree(req->buf);
			xfree(req);
			continue;
		}

		pr_debug("retrying 0x%llx nr_pages=%lu op=%s buf=%p\n",
		       req->address, req->nr_pages, req->buf ? "copy" : "zero", req->buf);

		/* Call appropriate retry function based on operation type */
		if (req->buf)
			ret = retry_uffd_copy(req);
		else
			ret = retry_uffd_zero(req);

		if (ret == -EAGAIN) {
			/* Still blocked - keep in queue for next attempt */
			pr_debug("still blocked 0x%llx\n", req->address);
			continue;
		} else if (ret < 0) {
			pr_err("EAGAIN retry error for 0x%llx, removing from queue\n",
			       req->address);
			BUG();
			list_del(&req->l);
			if (req->buf)
				xfree(req->buf);
			xfree(req);
			continue;
		}

		pr_debug("succeeded 0x%llx nr_pages=%lu\n",
		       req->address, req->nr_pages);

		list_del(&req->l);
		if (req->buf)
			xfree(req->buf);
		xfree(req);
	}

	pthread_mutex_unlock(&eagain_mutex);

	return 0;
}

/*
 * CLONE Restore State Management
 *
 * State variables and accessors for CLONE phased migration.
 * These track the state of the restore process and communication with the source.
 */

/* State flags for CLONE restore synchronization */
static bool clone_restore_connected = false;
static bool clone_all_pages_sent_received = false;

/* Check if restore has connected (uffd available) */
bool clone_is_restore_connected(void)
{
	return clone_restore_connected;
}

/* Set restore connected flag */
void clone_set_restore_connected(bool connected)
{
	clone_restore_connected = connected;
}

/* Check if all pages have been sent by the source */
bool clone_is_all_pages_sent_received(void)
{
	return clone_all_pages_sent_received;
}

/* Set all_pages_sent flag (called when PS_IOV_ALL_PAGES_SENT received) */
void clone_set_all_pages_sent_received(void)
{
	pr_info("All pages sent signal received - can zero-fill new VMA pages\n");
	clone_all_pages_sent_received = true;
}

/* Return uffd for a given vaddr (for background drain thread) */
int clone_get_uffd_for_vaddr(struct list_head *lpis, unsigned long vaddr)
{
	struct lazy_pages_info *lpi = clone_find_lpi_for_vaddr(lpis, vaddr);
	return lpi ? lpi->lpfd.fd : -1;
}

/*
 * CLONE Phase 2/3 Infrastructure
 *
 * Pre-buffer and convergence infrastructure for CLONE phased migration.
 * Pages arrive before criu restore connects, so we buffer them
 * in the hash table until the uffd is available.
 */

/*
 * Initialize the control message reader on the main page server socket.
 * All page data flows through P3 receiver threads; the main socket only
 * carries control messages (end-of-transfer marker, PS_IOV_ALL_PAGES_SENT).
 */
int clone_setup_prebuffer_reader(void)
{
	return page_server_start_async_read_bulk();
}


/*
 * Signal lazy-pages that tasks are frozen, wait for drain complete.
 * Called from lazy_pages_finish_restore() after catch_tasks().
 * Returns: 0 on success, -1 on error
 */
int clone_wait_for_drain(int fd)
{
	uint32_t tasks_frozen = LAZY_PAGES_TASKS_FROZEN;
	uint32_t drain_signal;
	int ret;

	ret = send(fd, &tasks_frozen, sizeof(tasks_frozen), 0);
	if (ret != sizeof(tasks_frozen)) {
		pr_perror("Failed sending TASKS_FROZEN signal");
		return -1;
	}

	ret = recv(fd, &drain_signal, sizeof(drain_signal), MSG_WAITALL);
	if (ret != sizeof(drain_signal)) {
		pr_perror("Failed receiving drain complete signal");
		return -1;
	}

	if (drain_signal != LAZY_PAGES_DRAIN_COMPLETE) {
		pr_err("Unexpected signal: %x\n", drain_signal);
		return -1;
	}

	return 0;
}

/*
 * Handle page fault in CLONE mode.
 * Serves page from buffer or zeros if not found.
 * Returns: 0 on success, -1 on error
 */
int clone_handle_page_fault(struct lazy_pages_info *lpi, unsigned long address)
{
	void *page_data;
	int ret;

	page_data = clone_page_buffer_lookup_and_remove(address);
	if (page_data) {
		page_state_set(address, PAGE_STATE_PF_PENDING);
		ret = clone_uffd_copy(lpi->lpfd.fd, address, page_data, 1,
				      lpi, NULL, 0, "PAGE_FAULT");
		page_pool_put(page_data);
		return ret < 0 ? -1 : 0;
	}

	return uffd_zero(lpi, address, 1);
}

/*
 * Handle UNMAP/REMOVE event in CLONE mode.
 * Marks pages as unmapped in trackers and removes from buffer.
 */
void clone_handle_remove_event(unsigned long start, unsigned long len)
{
	/* Mark all pages in range as unmapped for state tracking */
	page_state_mark_range_unmapped(start, len);

	/* Track unmapped pages for production validation */
	unmapped_tracker_mark_range(start, len);

	/* Remove these pages from buffer - no point draining them */
	clone_page_buffer_remove_range(start, len);
}

/*
 * CLONE post-connect initialization in handle_lazy_accept.
 * and Phase 3 page requests.
 *
 * Returns: 0 on success, -1 on error
 */
int clone_handle_lazy_accept_post_connect(struct list_head *lpis)
{
	/*
	 * Start drain thread if all pages have been sent.
	 * Skip switch_to_convergence() - the async bulk reader was already
	 * cleaned up when we received all_pages_sent, and we don't need it
	 * anymore since all pages are in the buffer.
	 */
	if (clone_is_all_pages_sent_received())
		clone_start_drain_thread(lpis);

	return 0;
}

/*
 * CLONE Phase 3 - Restore loop functions
 * Moved from uffd.c to reduce diff
 */

static struct epoll_rfd lazy_listen_rfd;

static int handle_lazy_accept(struct epoll_rfd *rfd)
{
	struct epoll_rfd *lazy_sk_rfd = uffd_get_lazy_sk_rfd();
	int epollfd = uffd_get_epollfd();
	int client;
	int i;
	struct sockaddr_un saddr;
	socklen_t len = sizeof(saddr);

	client = accept(rfd->fd, (struct sockaddr *)&saddr, &len);
	if (client < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		pr_perror("accept failed");
		return -1;
	}

	/* Set up lpi for each task (reads uffd from restore) */
	{
		int uffd_count = 0;
		for (i = 0; i < task_entries->nr_tasks; i++) {
			struct lazy_pages_info *lpi = NULL;

			if (uffd_open_task(client, &lpi))
				goto err;
			if (lpi == NULL)
				continue;
			if (epoll_add_rfd(epollfd, &lpi->lpfd))
				goto err;

			lp_debug(lpi, "registered UFFD handler (fd=%d)\n", lpi->lpfd.fd);
			uffd_count++;
		}
		pr_info("Registered %d UFFD handlers\n", uffd_count);
	}

	/* Set up restore-finished notification socket */
	lazy_sk_rfd->fd = client;
	lazy_sk_rfd->read_event = uffd_lazy_sk_read_event;
	lazy_sk_rfd->hangup_event = uffd_lazy_sk_hangup_event;
	if (epoll_add_rfd(epollfd, lazy_sk_rfd))
		goto err;

	epoll_del_rfd(epollfd, rfd);
	close(rfd->fd);

	clone_set_restore_connected(true);
	pr_info("Restore connected, %lu pages buffered\n", clone_page_buffer_count());

	return 0;

err:
	close(client);
	return -1;
}

static void clone_unregister_all_uffds(void)
{
	struct list_head *lpis = uffd_get_lpis();
	struct lazy_pages_info *lpi;
	struct lazy_iov *iov;

	list_for_each_entry(lpi, lpis, l) {
		if (lpi->exited || lpi->lpfd.fd < 0)
			continue;

		list_for_each_entry(iov, &lpi->iovs, l) {
			struct uffdio_range unreg = {
				.start = iov->start,
				.len = iov->end - iov->start,
			};

			if (ioctl(lpi->lpfd.fd, UFFDIO_UNREGISTER, &unreg)) {
				if (errno != ENOMEM)
					lp_perror(lpi, "UFFDIO_UNREGISTER 0x%lx-0x%lx",
						  iov->start, iov->end);
			}
		}
	}
}

int clone_phase3_restore_loop(int ep_fd, struct epoll_event **events, int nr_fds)
{
	struct epoll_rfd *lazy_sk_rfd = uffd_get_lazy_sk_rfd();
	int lazy_sk;
	int flags;
	int ret;

	uffd_set_epollfd(ep_fd);

	lazy_sk = uffd_prepare_listen_socket();
	if (lazy_sk < 0) {
		pr_err("Failed to create lazy socket\n");
		return -1;
	}

	flags = fcntl(lazy_sk, F_GETFL, 0);
	fcntl(lazy_sk, F_SETFL, flags | O_NONBLOCK);

	lazy_listen_rfd.fd = lazy_sk;
	lazy_listen_rfd.read_event = handle_lazy_accept;
	if (epoll_add_rfd(ep_fd, &lazy_listen_rfd)) {
		close(lazy_sk);
		return -1;
	}

	/* Wait for restore to connect */
	while (!clone_is_restore_connected()) {
		ret = epoll_run_rfds(ep_fd, *events, nr_fds, CLONE_LAZY_ACCEPT_POLL_MS);
		if (ret < 0) {
			pr_err("epoll failed waiting for restore\n");
			close(lazy_sk);
			return -1;
		}
	}

	/* Wait for drain to complete */
	while (clone_drain_thread_running() || clone_page_buffer_count() > 0) {
		ret = epoll_run_rfds(ep_fd, *events, nr_fds, 10);
		if (ret < 0) {
			pr_err("epoll failed during drain\n");
			return -1;
		}

		if (!clone_is_eagain_queue_empty()) {
			if (clone_process_eagain_requests()) {
				pr_err("EAGAIN processing failed\n");
				return -1;
			}
		}
	}

	page_pool_dump_utilization();
	clone_unregister_all_uffds();

	/* Signal restore that drain is complete */
	{
		uint32_t drain_complete = LAZY_PAGES_DRAIN_COMPLETE;
		if (send(lazy_sk_rfd->fd, &drain_complete, sizeof(drain_complete), 0) != sizeof(drain_complete))
			pr_perror("Failed to send drain complete signal");
	}

	return 0;
}
