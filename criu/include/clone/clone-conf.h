/*
 * CLONE Configuration Constants
 *
 * This header consolidates all CLONE configuration constants
 * from the phased migration implementation. Constants are
 * organized by category for maintainability.
 *
 * All CLONE source files should include this header and use these
 * constants instead of defining their own or using magic numbers.
 *
 * Note: Source files must include "page.h" before this header
 * for PAGE_SIZE-dependent constants (CLONE_BATCH_SIZE, CLONE_PAGES_PER_CHUNK).
 */

#ifndef __CR_CLONE_CONF_H__
#define __CR_CLONE_CONF_H__

#include <stdbool.h>

/* ================================================================
 * SECTION 0: Compile-time Feature Flags
 * ================================================================
 * These flags enable/disable optional CLONE features at compile time.
 * Uncomment to enable, comment out to disable.
 */

/*
 * CONFIG_PAGE_STATE_TRACKER - Enable page state tracking for debugging.
 * Tracks all state transitions and validates them to detect bugs.
 * Adds overhead, use only for debugging.
 */
// #define CONFIG_PAGE_STATE_TRACKER

/*
 * CLONE_PRE_SCAN - Iterative dirty scanning before freeze.
 * Now runtime-configurable via --clone-pre-scan CLI option (clone_cfg.pre_scan).
 * When enabled: Scanners do iterative PAGEMAP_SCAN while process runs,
 *               waiting for dirty pages to converge below threshold before
 *               requesting freeze.
 * When disabled (default): Scanners wait for freeze signal immediately after
 *               bulk transfer completes, then do a single final PAGEMAP_SCAN
 *               on the frozen process. This is faster and simpler.
 */

/*
 * CONFIG_HUNG_PAGE_TRACKER - Enable hung page detection.
 * Tracks pages that take too long to be processed.
 * Adds overhead, use only for debugging.
 */
// #define CONFIG_HUNG_PAGE_TRACKER

/* ================================================================
 * SECTION 1: Batch Transfer Configuration
 * ================================================================ */

/* Pages per batch for bulk transfer (1MB when PAGE_SIZE=4KB) */
#define CLONE_BATCH_PAGES			256
#define CLONE_BATCH_SIZE			(CLONE_BATCH_PAGES * PAGE_SIZE)

/* ================================================================
 * SECTION 2: Thread Count Configuration
 * ================================================================ */

/*
 * Thread counts are now runtime-configurable via CLI options:
 *   --clone-p3-threads, --clone-p3-threads-bulk, --clone-scanners,
 *   --clone-pre-scanners, --clone-drain-threads
 *
 * The MAX defines below are used for static array sizing only.
 * Runtime values are accessed via clone_cfg_*() functions from clone-conf.h.
 *
 * Defaults (used when CLI options are not specified):
 *   15 P3, 15 P3-bulk, 20 scanners, 1 pre-scanner, 20 drain
 */

/* Maximum values for static array declarations */
#define CLONE_MAX_P3_THREADS		20
#define CLONE_MAX_SCANNERS		24
#define CLONE_MAX_DRAIN_THREADS		24
#define CLONE_MAX_THREADS			64

/* Default values (used when CLI options are not specified) */
#define CLONE_DEFAULT_P3_THREADS			15
#define CLONE_DEFAULT_P3_THREADS_BULK		15
#define CLONE_DEFAULT_SCANNERS			20
#define CLONE_DEFAULT_PRE_SCANNERS		1
#define CLONE_DEFAULT_DRAIN_THREADS		20

/*
 * Number of queues per scanner (producer). Scanner i owns queues
 * [i*CLONE_QUEUES_PER_THREAD, (i+1)*CLONE_QUEUES_PER_THREAD). Total is
 * driven by the producer count so every queue has exactly one producer;
 * consumers (P3 threads) round-robin over the full set.
 */
#define CLONE_QUEUES_PER_THREAD		5
#define CLONE_TOTAL_QUEUES		(CLONE_MAX_SCANNERS * CLONE_QUEUES_PER_THREAD)

/* Maximum epoll fds for CLONE lazy-pages */
#define CLONE_MAX_EPOLL_FDS		128

/* ================================================================
 * SECTION 3: Memory Pool Configuration
 * ================================================================ */

/* Chunk sizes for page pool */
#define CLONE_CHUNK_SIZE			(64UL * 1024 * 1024)   /* 64MB per chunk */
#define CLONE_CHUNK_ALIGN			CLONE_CHUNK_SIZE
#define CLONE_CHUNK_ALIGN_MASK		(~(CLONE_CHUNK_ALIGN - 1))

/* Allocation batching */
#define CLONE_ALLOC_BATCH			256  /* Pages per allocation batch (1MB) */

/* Maximum chunks (8192 * 64MB = 512GB max memory) */
#define CLONE_MAX_POOL_CHUNKS		8192

/* Per-worker page pool size */
#define CLONE_PAGE_POOL_SIZE		256  /* 256 x 4KB = 1MB per worker */

/* Derived: pages per chunk */
#define CLONE_PAGES_PER_CHUNK		(CLONE_CHUNK_SIZE / PAGE_SIZE)

/* Write-protect chunk size for parallel application */
#define CLONE_WP_CHUNK_SIZE		(64UL * 1024 * 1024)  /* 64MB */

/* ================================================================
 * SECTION 4: Hash Table Configuration
 * ================================================================ */

/*
 * Batch buffer: hash table stores 1MB-aligned entries.
 * Each entry holds 256 contiguous pages with a bitmap tracking validity.
 * Drain can UFFDIO_COPY 1MB at once instead of per-page.
 */
#define CLONE_BATCH_SHIFT			20  /* log2(CLONE_BATCH_SIZE) = log2(1MB) */
#define CLONE_BATCH_ALIGN_MASK		(~((1UL << CLONE_BATCH_SHIFT) - 1))

/* 256K buckets: ~5 entries/bucket at 300GB (1.2M entries) */
#define CLONE_BATCH_BUFFER_HASH_BITS	18
#define CLONE_BATCH_BUFFER_HASH_SIZE	(1 << CLONE_BATCH_BUFFER_HASH_BITS)

/* Fine-grained locking for batch buffer - 1:1 lock per bucket to minimize contention */
#define CLONE_BATCH_NUM_HASH_LOCKS	CLONE_BATCH_BUFFER_HASH_SIZE
#define CLONE_BATCH_BUCKETS_PER_LOCK	1

/* Page state tracker hash table */
#define CLONE_PAGE_STATE_HASH_BITS	18
#define CLONE_PAGE_STATE_HASH_SIZE	(1 << CLONE_PAGE_STATE_HASH_BITS)
#define CLONE_PAGE_STATE_MAX		10
#define CLONE_PAGE_STATE_HISTORY_SIZE	16  /* Max history entries per page */

/* Unmapped tracker hash table */
#define CLONE_NUM_UNMAPPED_LOCKS		512
#define CLONE_UNMAPPED_BUCKETS_PER_LOCK	128

/* ================================================================
 * SECTION 5: Convergence Thresholds
 * ================================================================ */

/* Dirty page scan freeze threshold (request freeze when below this) */
#define CLONE_DIRTY_SCAN_FREEZE_THRESHOLD	2000000

/* Legacy per-thread convergence threshold */
#define CLONE_DIRTY_CONVERGENCE_THRESHOLD	50000

/* Low dirty pages threshold for extended sleep */
#define CLONE_LOW_DIRTY_THRESHOLD		1000

/* Max iterations before extended sleep */
#define CLONE_MAX_DIRTY_ITERATIONS	3

/* Maximum pre-scan iterations before forcing freeze (0 = unlimited) */
#define CLONE_PRE_SCAN_MAX_ITERATIONS	2

/* ================================================================
 * SECTION 6: Pre-read Configuration
 * ================================================================ */

/* Pre-read window: 8 pages before + faulting page + 7 pages after = 16 pages */
#define CLONE_PREREAD_BEFORE		8
#define CLONE_PREREAD_AFTER		7
#define CLONE_PREREAD_TOTAL		(CLONE_PREREAD_BEFORE + 1 + CLONE_PREREAD_AFTER)

/* ================================================================
 * SECTION 7: Timing Configuration (microseconds unless noted)
 * ================================================================ */

/* Short yield intervals */
#define CLONE_USLEEP_100US		100	/* 100us - queue empty, drain yield */
#define CLONE_USLEEP_1MS			1000	/* 1ms - UFFD unregister, dirty scan poll */
#define CLONE_USLEEP_10MS			10000	/* 10ms - bulk transfer poll */
#define CLONE_USLEEP_CONVERGENCE		30000	/* 30ms - convergence sleep */

/* Timeout values (milliseconds) */
#define CLONE_P3_ACCEPT_TIMEOUT_MS	5000	/* 5 seconds */
#define CLONE_LAZY_ACCEPT_POLL_MS	1000	/* epoll poll interval while waiting for restore connect */

/* Stats/logging intervals (seconds) */
#define CLONE_STATS_PRINT_SEC		30	/* UFFD stats */
#define CLONE_DRAIN_PROGRESS_SEC		10	/* Drain progress */

/* ================================================================
 * SECTION 8: VMA Processing
 * ================================================================ */

/* Minimum VMA size for thread splitting (smaller VMAs go to thread 0) */
#define CLONE_MIN_VMA_SIZE_FOR_SPLIT	(256 * 1024)  /* 256KB */

/* PAGEMAP_SCAN max regions per call */
#define CLONE_PAGEMAP_SCAN_VEC_LEN	1000

/* PAGEMAP_SCAN max pages per call - first iteration vs subsequent iterations */
#define CLONE_PAGEMAP_SCAN_MAX_PAGES_ITER1	16384
#define CLONE_PAGEMAP_SCAN_MAX_PAGES_ITER_N	512

/* PAGEMAP_SCAN max address range per ioctl call (4MB = 2 PMDs)
 * This bounds mmap_lock hold time regardless of dirty page density.
 * Unlike max_pages which only limits output, this limits actual scan work.
 */
#define CLONE_PAGEMAP_SCAN_RANGE_SIZE	(4UL * 1024 * 1024)

/* Initial capacity for ranges arrays */
#define CLONE_INITIAL_RANGES_CAPACITY	64

/* UFFD unregister yield interval (every N VMAs) */
#define CLONE_UFFD_UNREGISTER_YIELD	10

/* Scale yield interval up by 1 for each N tracked VMAs (handles huge VMA lists) */
#define CLONE_UFFD_YIELD_VMA_DIVISOR	1000

/* Drain batch size in VMA processing */
#define CLONE_DRAIN_BATCH_SIZE		100

/* ================================================================
 * SECTION 9: Work-Stealing Configuration
 * ================================================================ */

/* Work chunk size for bulk transfer load balancing (32MB) */
#define CLONE_WORK_CHUNK_SIZE		(32UL * 1024 * 1024)
#define CLONE_WORK_CHUNK_PAGES		(CLONE_WORK_CHUNK_SIZE / PAGE_SIZE)

/* Maximum work queue items for bulk transfer */
#define CLONE_MAX_WORK_ITEMS		16384

/* ================================================================
 * SECTION 10: Logging/Debug Thresholds
 * ================================================================ */

/* Sample rates for high-frequency logging (modulo values) */
#define CLONE_LOG_SAMPLE_1M		1000000	/* Every 1M operations */
#define CLONE_LOG_SAMPLE_100K		100000	/* Every 100K operations */
#define CLONE_LOG_SAMPLE_10K		10000	/* Every 10K operations */
#define CLONE_LOG_SAMPLE_1K		1000	/* Every 1K operations */

/* Progress logging intervals */
#define CLONE_PROGRESS_LOG_INTERVAL	1000

/* Debug exit frequency */
#define CLONE_EXIT_DEBUG_FREQUENCY	100

/* ================================================================
 * SECTION 11: Refcount Warning Thresholds (page-pool.c)
 * ================================================================ */

#define CLONE_REFCOUNT_LOW		1000
#define CLONE_REFCOUNT_MID		30000

/* ================================================================
 * SECTION 12: Cache Line Padding
 * ================================================================ */

/* Cache line size for struct padding to avoid false sharing */
#define CLONE_CACHE_LINE_SIZE		64

/* SPSC queue padding (2 cache lines) */
#define CLONE_SPSC_PADDING		128

/* ================================================================
 * SECTION 13: Runtime Thread Configuration
 * ================================================================ */

/*
 * Runtime-configurable thread counts, initialized from CLI options.
 * Access via clone_cfg() after clone_cfg_init() has been called.
 */
struct clone_runtime_cfg {
	int num_p3_threads;
	int num_p3_threads_bulk;
	int num_scanners;
	int num_pre_scanners;
	int num_drain_threads;
	bool pre_scan;
};

#ifdef CONFIG_HAS_LZ4

extern struct clone_runtime_cfg clone_cfg;

void clone_cfg_init(int p3_threads, int p3_threads_bulk,
		  int scanners, int pre_scanners, int drain_threads,
		  bool pre_scan);

/*
 * Initialize and validate clone runtime config from CLI options.
 * Returns 0 on success, -1 on validation error.
 */
int clone_cfg_init_from_opts(int p3, int p3_bulk, int scan,
			   int pre_scan_threads, int drain, bool pre_scan);

#else /* !CONFIG_HAS_LZ4 */

/* Stubs when LZ4/CLONE support is not compiled in */
static inline void clone_cfg_init(int p3_threads, int p3_threads_bulk,
				  int scanners, int pre_scanners,
				  int drain_threads, bool pre_scan)
{
	(void)p3_threads; (void)p3_threads_bulk; (void)scanners;
	(void)pre_scanners; (void)drain_threads; (void)pre_scan;
}

static inline int clone_cfg_init_from_opts(int p3, int p3_bulk, int scan,
					   int pre_scan_threads, int drain,
					   bool pre_scan)
{
	(void)p3; (void)p3_bulk; (void)scan;
	(void)pre_scan_threads; (void)drain; (void)pre_scan;
	return -1;
}

#endif /* CONFIG_HAS_LZ4 */

#endif /* __CR_CLONE_CONF_H__ */
