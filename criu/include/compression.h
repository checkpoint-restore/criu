#ifndef __CR_COMPRESSION_H__
#define __CR_COMPRESSION_H__

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "common/lock.h"
#include "page.h"

/*
 * Compression mode for memory pages. Stored in opts.compress_mode and
 * encoded in inventory_entry.compress and criu_opts.compress on the wire.
 *
 * Single source of truth: COMPRESS_OFF (=0) means no compression. There
 * is no separate "compression enabled" boolean; sites that want a
 * predicate use `if (opts.compress_mode)`.
 */
enum compress_mode {
	COMPRESS_OFF		= 0,
	COMPRESS_PER_PAGE	= 1,
	COMPRESS_REGION		= 2,
};

/* Keep region memory and CLI limits stable across host page sizes. */
#define MAX_REGION_SIZE		(4UL * 1024 * 1024)
#define DEFAULT_REGION_SIZE	(256UL * 1024)
#define MAX_REGION_PAGES	(MAX_REGION_SIZE / PAGE_SIZE)
#define DEFAULT_REGION_PAGES	(DEFAULT_REGION_SIZE / PAGE_SIZE)

/* Minimum useful batch before starting compressed-page restore workers. */
#define PARALLEL_RESTORE_MIN_BATCH_BYTES (1UL << 20)

/* LZ4 worst-case compressed size for one page: src + src/255 + 16 */
#define PAGE_COMPRESSED_SIZE_BOUND (PAGE_SIZE + (PAGE_SIZE / 255) + 16)

/*
 * LZ4 worst-case compressed size for a region of n_pages pages.
 * Same formula as PAGE_COMPRESSED_SIZE_BOUND but with n_pages*PAGE_SIZE
 * as the input size.
 */
#define REGION_COMPRESSED_SIZE_BOUND(n_pages) \
	((size_t)(n_pages) * PAGE_SIZE + ((size_t)(n_pages) * PAGE_SIZE / 255) + 16)

/*
 * Compression threshold: store raw if compressed size is at or above this.
 * Pages that only compress by a small amount are not worth the
 * decompression cost on restore.
 */
#define PAGE_COMPRESSION_THRESHOLD (PAGE_SIZE * 7 / 8)
#define REGION_COMPRESSION_THRESHOLD(region_bytes) ((region_bytes) * 7 / 8)

/*
 * Default LZ4 acceleration level for LZ4_compress_fast().
 * Acceleration controls how many positions the compressor
 * probes in its hash table when searching for matches.
 * Value 1 performs the most thorough search and gives the best ratio.
 * Higher values skip more match candidates, resulting in
 * faster compression but fewer and shorter matches.
 * The acceleration setting does not affect decompression.
 * Valid range: 1 to LZ4_MAX_ACCELERATION.
 */
#define LZ4_MAX_ACCELERATION	65537
#define LZ4_DEFAULT_ACCELERATION 1

/*
 * Detect zero-filled pages. Use memcpy() for word loads so callers can
 * pass stack buffers without requiring unsigned-long alignment.
 */
static inline bool page_is_all_zero(const char *page)
{
	unsigned int last = PAGE_SIZE / sizeof(unsigned long) - 1;
	unsigned long word;
	unsigned int i;

	/*
	 * Check last word first: pages are often zero at the start
	 * but have non-zero data near the end (e.g. stack, heap).
	 * See kernel commit 0ca0c24e3211 ("mm: zswap: check the last
	 * page in a folio first").
	 */
	__builtin_memcpy(&word, page + (size_t)last * sizeof(word), sizeof(word));
	if (word)
		return false;

	for (i = 0; i < last; i++) {
		__builtin_memcpy(&word, page + (size_t)i * sizeof(word), sizeof(word));
		if (word)
			return false;
	}
	return true;
}

/*
 * One block that can be restored independently. Jobs passed together must
 * write to disjoint destinations. A zero compressed size clears the block;
 * other jobs hold LZ4 payloads. Raw-fallback blocks remain caller-owned.
 */
struct decompress_job {
	const char *src;
	char *dst;
	uint32_t compressed_size;
	uint16_t pages;
	int block_index;
};

struct decompression_pool;
typedef void (*decompression_caller_work_fn)(void *arg);

/*
 * Restore-wide limits live in the shared restore mapping. All task restore
 * processes and asyncd workers inherit the same object, bounding active
 * compressed-page workers and large encoded working sets across siblings.
 */
struct decompression_shared_budget {
	futex_t threads;
	futex_t batches;
	/* Immutable capacity used for restore-path selection. */
	unsigned int thread_capacity;
};

#ifdef CONFIG_LZ4

int compress_data(const char *input_data, size_t input_size,
		  char *compressed_data, size_t output_size,
		  int acceleration);
int decompress_data(const char *compressed_data, int compressed_size,
		    int original_size, char *decompressed_data);

/*
 * Compress @n_pages pages from @src into one LZ4 region block.
 *
 * Returns the size to store in compressed_size[]:
 * - 0: all-zero region, no payload
 * - n_pages * PAGE_SIZE: raw payload in @dst
 * - otherwise: LZ4 payload in @dst
 *
 * Returns -1 on error.
 */
int compress_region(const char *src, unsigned int n_pages, char *dst,
		    size_t dst_cap, int acceleration);

/*
 * Inverse of compress_region(). @compressed_size is the value the
 * caller stored at compression time. Always writes n_pages*PAGE_SIZE
 * bytes into @dst.
 */
int decompress_region(const char *src, int compressed_size,
		      unsigned int n_pages, char *dst);

/*
 * Reuse worker threads through @pool across related batches. A later wider
 * batch may replace the pool. @requested_threads includes the caller; zero
 * selects automatic concurrency and one keeps the call serial. The active
 * width is bounded by available CPUs, useful batch work, and the shared CPU
 * budget. Small batches run serially. Calls sharing a pool must be serialized.
 * @pool must initially be NULL and must be destroyed before the caller forks
 * or remaps its address space.
 */
int decompress_jobs_parallel_pool(struct decompression_pool **pool,
				  struct decompress_job *jobs,
				  size_t nr_jobs,
				  size_t total_uncompressed,
				  unsigned int requested_threads);
/*
 * After dispatching a parallel batch, run @caller_work once in the calling
 * thread before it helps the pool. Serial fallbacks skip the callback. The
 * callback must record its own result and must not mutate @jobs, re-enter
 * @pool, or acquire another worker-budget reservation.
 */
int decompress_jobs_parallel_pool_with_caller_work(
	struct decompression_pool **pool, struct decompress_job *jobs,
	size_t nr_jobs, size_t total_uncompressed,
	unsigned int requested_threads,
	decompression_caller_work_fn caller_work, void *caller_work_arg);
void decompression_pool_destroy(struct decompression_pool *pool);
/*
 * Initialize the restore-wide CPU and encoded-working-set budgets. Automatic
 * (0) and serial (1) per-call settings still permit independent restore
 * requests to run on separate CPUs; values above one cap their aggregate
 * worker width.
 */
void decompression_shared_budget_init(struct decompression_shared_budget *budget,
				      unsigned int requested_threads);
void decompression_use_shared_budget(struct decompression_shared_budget *budget);
void decompression_batch_acquire(void);
bool decompression_batch_try_acquire(void);
void decompression_batch_release(void);
bool compressed_restore_has_parallel_capacity(unsigned int requested_threads);

/* Apply the requested auto/explicit setting to the detected CPU capacity. */
unsigned int decompression_thread_limit(unsigned int requested,
					unsigned int available_cpus);

#else /* !CONFIG_LZ4 */

static inline int compress_data(const char *in, size_t in_sz, char *out,
				size_t out_sz, int acceleration)
{
	return -1;
}

static inline int decompress_data(const char *in, int in_sz, int out_sz,
				  char *out)
{
	return -1;
}

static inline int compress_region(const char *src, unsigned int n_pages,
				  char *dst, size_t dst_cap, int accel)
{
	return -1;
}

static inline int decompress_region(const char *src, int comp_sz,
				    unsigned int n_pages, char *dst)
{
	return -1;
}

static inline int decompress_jobs_parallel_pool(
	struct decompression_pool **pool, struct decompress_job *jobs,
	size_t nr_jobs, size_t total_uncompressed,
	unsigned int requested_threads)
{
	return -1;
}

static inline int decompress_jobs_parallel_pool_with_caller_work(
	struct decompression_pool **pool, struct decompress_job *jobs,
	size_t nr_jobs, size_t total_uncompressed,
	unsigned int requested_threads,
	decompression_caller_work_fn caller_work, void *caller_work_arg)
{
	return -1;
}

static inline void decompression_pool_destroy(struct decompression_pool *pool)
{
}

static inline void decompression_shared_budget_init(
	struct decompression_shared_budget *budget, unsigned int requested_threads)
{
}

static inline void decompression_use_shared_budget(
	struct decompression_shared_budget *budget)
{
}

static inline void decompression_batch_acquire(void)
{
}

static inline bool decompression_batch_try_acquire(void)
{
	return false;
}

static inline void decompression_batch_release(void)
{
}

static inline bool compressed_restore_has_parallel_capacity(
	unsigned int requested_threads)
{
	return false;
}

#endif /* CONFIG_LZ4 */

#endif /* __CR_COMPRESSION_H__ */
