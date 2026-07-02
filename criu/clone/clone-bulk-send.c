/*
 * CLONE bulk page sender (P3 transfer).
 *
 * Pages are sent in CLONE_BATCH_PAGES-sized batches: one process_vm_readv,
 * one LZ4 compression, one socket send per batch.
 *
 * Bulk-transfer phase uses a shared work queue of VMA chunks; sender threads
 * pull work dynamically, and idle threads can steal from other threads'
 * dirty-region queues during the iterative dirty-scan phase.
 */

#include <sched.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>
#include <lz4.h>

#include "int.h"
#include "page.h"
#include "types.h"
#include "criu-log.h"
#include "xmalloc.h"
#include "common/list.h"
#include "mem.h"
#include "clone/clone-bulk-send.h"
#include "page-xfer.h"
#include "clone/clone-page-xfer.h"
#include "clone/atomic-bitmap.h"
#include "cr_options.h"
#include "tls.h"
#include "clone/tls-conn.h"
#include "pagemap.h"
#include "pagemap_scan.h"
#include "common/bug.h"
#include "clone/clone-dump.h"

#undef LOG_PREFIX
#define LOG_PREFIX "clone-bulk: "

/*
 * CPU affinity helpers for bulk transfer phase.
 * During bulk transfer, sender threads are pinned to one CPU to avoid
 * using multiple cores (receiver is the bottleneck, not sender).
 * After bulk transfer, threads are unpinned to use all available CPUs.
 */
#ifdef CLONE_P3_SENDER_CPU
static void pin_to_cpu(int cpu)
{
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
}

static void unpin_cpu(void)
{
	cpu_set_t cpuset;
	int i, ncpus;

	ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	CPU_ZERO(&cpuset);
	for (i = 0; i < ncpus; i++)
		CPU_SET(i, &cpuset);
	pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
}
#endif

/*
 * Protocol structs, constants, and helpers are now in page-xfer.h:
 * - struct page_server_iov
 * - PS_CMD_BITS, encode_ps_cmd()
 * - page_server_send() (replaces __send)
 *
 * CLONE-specific protocol defines (PS_IOV_ADD_F_COMPRESS, etc.) are in clone-page-xfer.h
 * CLONE configuration constants (CLONE_BATCH_PAGES, etc.) are in clone-conf.h
 */

/*
 * Work-stealing chunk size: CLONE_WORK_CHUNK_SIZE (default 32MB).
 * Smaller chunks = better balancing but more overhead.
 * Larger chunks = less overhead but worse balancing.
 * Configuration in clone-conf.h.
 */

/* Per-thread state */
struct p3_thread_ctx {
	pthread_t thread;
	int thread_id;
	int socket;           /* Per-thread socket for parallel transfer */
	struct tls_conn *tls; /* Per-thread TLS session (NULL if TLS disabled) */
	u64 dst_id;
	pid_t source_pid;
	unsigned long pages_sent;
	volatile bool active;
	volatile bool error;  /* Set if thread encountered an error */
};

static struct p3_thread_ctx p3_threads[CLONE_MAX_P3_THREADS];
static volatile int p3_threads_active = 0;
static unsigned long p3_total_pages_sent = 0;

/* Global flag for signaling last scan (set by main thread after freeze) */
static volatile bool g_last_scan_flag = false;

/* Timestamp when freeze signal was sent - for P3 thread timing */
static struct timespec g_freeze_signal_time;

/* New VMA ranges detected in Phase 3 - set by main thread before last scan */
static unsigned long *g_new_vma_ranges = NULL;  /* [start, len, start, len, ...] */
static unsigned int g_nr_new_vma_ranges = 0;

/*
 * MPMC convergence queue: scanners push dirty_region_entry pointers,
 * consumers CAS-claim one entry at a time. Flat array + two atomic
 * counters. One CAS per real work item, no empty-queue waste.
 */
#define CONV_QUEUE_CAP	(8 * 1024 * 1024)
static struct dirty_region_entry **g_conv_slots;
static volatile unsigned long g_conv_head;
static volatile unsigned long g_conv_tail;

static volatile bool g_scan_complete = false;
static volatile bool g_scanner_freeze_signal = false;
static pid_t g_scanner_source_pid;

/* Atomic counter for total scanned pages (for verification) */
static volatile unsigned long g_total_scanned_pages = 0;
/* Atomic counter for total sent pages (for verification) */
static volatile unsigned long g_total_sent_pages = 0;

/* Dual scanner state */
struct scanner_ctx {
	int id;                    /* Scanner ID: 0 or 1 */
	pthread_t thread;
	int pagemap_fd;
	unsigned long dirty_count; /* Dirty pages found in current iteration */
	volatile bool finished;    /* Set when scanner thread exits */
};
static struct scanner_ctx scanners[CLONE_MAX_SCANNERS];

/* Synchronization: scanners coordinate on iteration and freeze */
static volatile int g_scanners_iter_done = 0;  /* Count of scanners done with iteration */
static volatile unsigned long g_total_dirty_pages = 0;  /* Sum of dirty pages */
static pthread_mutex_t g_scanner_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_scanner_cond = PTHREAD_COND_INITIALIZER;

/* Synchronization: scanner waits for bulk transfer to complete */
static volatile int g_bulk_transfer_done_count = 0;
static volatile int g_num_sender_threads = 0;

/*
 * Pages that were scanned/work-queued but could not be sent because the
 * VMA disappeared between enumeration and process_vm_readv (ADD/REMOVE
 * race: the source process calls munmap during Phase 2 before the UFFD
 * REMOVE event is observed by any code path on the dump side; UFFD events
 * are consumed only on the target side, so from the source dumper's point
 * of view the kernel is the authority via EFAULT/ESRCH/ENOMEM from
 * process_vm_readv).
 *
 * Counted so clone_wait_p3_threads' scanned==sent invariant is not
 * violated by a legitimate skip.
 */
static volatile unsigned long g_vma_vanished_skipped_pages = 0;

static inline bool clone_errno_is_vma_gone(int err)
{
	return err == EFAULT || err == ESRCH || err == ENOMEM;
}

/*
 * Work-stealing infrastructure for bulk transfer phase.
 * Instead of statically assigning VMA chunks to threads, we create a shared
 * work queue of chunks that threads pull from dynamically.
 */
struct bulk_work_item {
	struct lazy_vma_entry *lve;
	unsigned long start;
	unsigned long end;
};

static struct bulk_work_item g_work_queue[CLONE_MAX_WORK_ITEMS];
static volatile int g_work_queue_size = 0;
static volatile int g_work_queue_next = 0;  /* Next item to dequeue (atomic) */

/*
 * Build the work queue by splitting all VMAs into CLONE_WORK_CHUNK_SIZE pieces.
 * Must be called before starting sender threads.
 */
static void build_bulk_work_queue(u64 dst_id)
{
	struct list_head *lazy_vmas = clone_mem_get_lazy_vmas();
	struct lazy_vma_entry *lve;
	int count = 0;

	list_for_each_entry(lve, lazy_vmas, list) {
		unsigned long vaddr;

		if (lve->dst_id != dst_id)
			continue;

		/* Split VMA into CLONE_WORK_CHUNK_SIZE pieces */
		for (vaddr = lve->start; vaddr < lve->end; vaddr += CLONE_WORK_CHUNK_SIZE) {
			unsigned long chunk_end = vaddr + CLONE_WORK_CHUNK_SIZE;

			if (chunk_end > lve->end)
				chunk_end = lve->end;

			if (count >= CLONE_MAX_WORK_ITEMS) {
				pr_err("Work queue overflow! Increase CLONE_MAX_WORK_ITEMS\n");
				BUG();
			}

			g_work_queue[count].lve = lve;
			g_work_queue[count].start = vaddr;
			g_work_queue[count].end = chunk_end;
			count++;
		}
	}

	g_work_queue_size = count;
	g_work_queue_next = 0;
	pr_info("Built bulk work queue: %d chunks of %luMB max\n",
		count, CLONE_WORK_CHUNK_SIZE / (1024 * 1024));
}

/*
 * Get next work item from the shared queue (thread-safe).
 * Returns NULL when queue is exhausted.
 */
static struct bulk_work_item *get_next_work_item(void)
{
	int idx = __atomic_fetch_add(&g_work_queue_next, 1, __ATOMIC_RELAXED);

	if (idx >= g_work_queue_size)
		return NULL;

	return &g_work_queue[idx];
}

int clone_init_sender_queues(void)
{
	g_conv_slots = xzalloc(CONV_QUEUE_CAP * sizeof(g_conv_slots[0]));
	BUG_ON(!g_conv_slots);
	g_conv_head = 0;
	g_conv_tail = 0;
	g_scan_complete = false;
	g_scanner_freeze_signal = false;
	pr_info("Initialized MPMC convergence queue (%d slots)\n",
		CONV_QUEUE_CAP);
	return 0;
}

static struct dirty_region_entry *conv_queue_pop(void)
{
	unsigned long t, h;

	t = __atomic_load_n(&g_conv_tail, __ATOMIC_RELAXED);
	h = __atomic_load_n(&g_conv_head, __ATOMIC_ACQUIRE);
	if (t >= h)
		return NULL;
	if (!__atomic_compare_exchange_n(&g_conv_tail, &t, t + 1,
					 false, __ATOMIC_ACQUIRE,
					 __ATOMIC_RELAXED))
		return NULL;

	{
		struct dirty_region_entry *entry;
		while (!(entry = __atomic_load_n(&g_conv_slots[t], __ATOMIC_ACQUIRE)))
			;
		return entry;
	}
}

bool clone_is_scan_complete(void)
{
	return __atomic_load_n(&g_scan_complete, __ATOMIC_ACQUIRE);
}

void clone_signal_scanner_freeze(void)
{
	pr_debug("Scanner: signaling freeze\n");
	__atomic_store_n(&g_scanner_freeze_signal, true, __ATOMIC_RELEASE);
	__sync_synchronize();
}

/*
 * Scanner thread. Each scanner:
 *   - Scans its own disjoint slice of every lazy VMA's address range
 *     (slice = vma_size / clone_cfg.num_scanners, last scanner gets the remainder).
 *   - Enqueues dirty regions into the shared MPMC convergence queue,
 *     namely [scanner_id * CLONE_QUEUES_PER_THREAD, scanner_id * CLONE_QUEUES_PER_THREAD
 *     + CLONE_QUEUES_PER_THREAD). This preserves the SPSC single-producer invariant:
 *     no two scanners ever enqueue to the same queue.
 */
static void *dirty_scanner_thread(void *arg)
{
	struct scanner_ctx *ctx = (struct scanner_ctx *)arg;
	int scanner_id = ctx->id;
	struct list_head *lazy_vmas;
	struct lazy_vma_entry *lve;
	struct page_region *regs;
	const int max_regs = CLONE_PAGEMAP_SCAN_VEC_LEN;
	unsigned int iteration = 0;
	char pagemap_path[64];
	struct timespec t_start, t_end;

	pr_debug("Scanner[%d] started, source_pid=%d\n",
	       scanner_id, g_scanner_source_pid);
	clock_gettime(CLOCK_MONOTONIC, &t_start);

	/* Wait for all sender threads to complete bulk transfer first */
	if (scanner_id == 0) {
		pr_debug("Scanner[0]: waiting for %d sender threads to complete bulk transfer...\n",
		       g_num_sender_threads);
	}
	while (__atomic_load_n(&g_bulk_transfer_done_count, __ATOMIC_ACQUIRE) <
	       __atomic_load_n(&g_num_sender_threads, __ATOMIC_ACQUIRE)) {
		if (__atomic_load_n(&g_scanner_freeze_signal, __ATOMIC_ACQUIRE))
			goto out;
		usleep(CLONE_USLEEP_10MS);
	}
	if (scanner_id == 0) {
		pr_debug("Scanner: all sender threads completed bulk transfer, starting dirty scan\n");
	}

	/* Open pagemap fd - each scanner needs its own fd */
	snprintf(pagemap_path, sizeof(pagemap_path), "/proc/%d/pagemap",
		 g_scanner_source_pid);
	ctx->pagemap_fd = open(pagemap_path, O_RDWR);
	if (ctx->pagemap_fd < 0) {
		pr_perror("Scanner[%d]: cannot open %s", scanner_id, pagemap_path);
		goto out;
	}

	regs = xmalloc(max_regs * sizeof(struct page_region));
	BUG_ON(!regs);

	lazy_vmas = clone_mem_get_lazy_vmas();

	if (!clone_cfg.pre_scan)
		goto wait_for_freeze;

	/* Only first clone_cfg.num_pre_scanners participate in pre-scan */
	if (scanner_id >= clone_cfg.num_pre_scanners)
		goto wait_for_freeze;

	/* Iterative dirty scanning until freeze signal */
	while (!__atomic_load_n(&g_scanner_freeze_signal, __ATOMIC_ACQUIRE)) {
		unsigned long my_dirty_pages = 0;
		struct timespec iter_start, iter_end;
		unsigned long scan_time_ns = 0;
		unsigned long dist_time_ns = 0;
		unsigned long num_regions = 0;

		iteration++;
		clock_gettime(CLOCK_MONOTONIC, &iter_start);

		/* Scan this scanner's portion of each VMA */
		list_for_each_entry(lve, lazy_vmas, list) {
			struct pm_scan_arg args;
			long regs_len;
			unsigned long vma_size = lve->end - lve->start;
			unsigned long total_pages = vma_size / PAGE_SIZE;
			unsigned long pages_per_scanner = total_pages / clone_cfg.num_pre_scanners;
			unsigned long my_start, my_end;

			/* Calculate this scanner's range (page-aligned) */
			my_start = lve->start + (scanner_id * pages_per_scanner * PAGE_SIZE);
			if (scanner_id == clone_cfg.num_pre_scanners - 1)
				my_end = lve->end;  /* Last pre-scanner gets remainder */
			else
				my_end = my_start + (pages_per_scanner * PAGE_SIZE);

			/* Skip if range is too small */
			if (my_end <= my_start)
				continue;

			/* Range-based chunking: iterate in CLONE_PAGEMAP_SCAN_RANGE_SIZE chunks
			 * to bound mmap_lock hold time regardless of dirty page density */
			for (unsigned long chunk_start = my_start; chunk_start < my_end;) {
				unsigned long chunk_end = chunk_start + CLONE_PAGEMAP_SCAN_RANGE_SIZE;
				if (chunk_end > my_end)
					chunk_end = my_end;

				memset(&args, 0, sizeof(args));
				args.size = sizeof(args);
				args.flags = PM_SCAN_WP_MATCHING;
				args.start = chunk_start;
				args.end = chunk_end;
				args.walk_end = chunk_start;
				args.vec = (u64)(unsigned long)regs;
				args.vec_len = max_regs;
				args.max_pages = (iteration == 1) ?
					CLONE_PAGEMAP_SCAN_MAX_PAGES_ITER1 :
					CLONE_PAGEMAP_SCAN_MAX_PAGES_ITER_N;
				args.category_anyof_mask = PAGE_IS_WRITTEN;
				args.return_mask = PAGE_IS_WRITTEN;

				do {
					struct timespec t1, t2, t3;
					int i;
					args.start = args.walk_end;

					clock_gettime(CLOCK_MONOTONIC, &t1);
					regs_len = ioctl(ctx->pagemap_fd, PAGEMAP_SCAN, &args);
					clock_gettime(CLOCK_MONOTONIC, &t2);
					scan_time_ns += (t2.tv_sec - t1.tv_sec) * 1000000000UL +
							(t2.tv_nsec - t1.tv_nsec);

					if (regs_len < 0) {
						pr_perror("Scanner[%d]: PAGEMAP_SCAN failed", scanner_id);
						break;
					}

					if (regs_len == 0)
						break;

					num_regions += regs_len;

					for (i = 0; i < regs_len; i++) {
						struct dirty_region_entry *entry;
						unsigned long pages;

						pages = (regs[i].end - regs[i].start) / PAGE_SIZE;
						my_dirty_pages += pages;

						entry = xmalloc(sizeof(*entry));
						BUG_ON(!entry);
						entry->start = regs[i].start;
						entry->end = regs[i].end;
						entry->dst_id = lve->dst_id;
						entry->source_pid = g_scanner_source_pid;

						{
							unsigned long slot = __atomic_fetch_add(&g_conv_head, 1, __ATOMIC_RELAXED);
							BUG_ON(slot >= CONV_QUEUE_CAP);
							__atomic_store_n(&g_conv_slots[slot], entry, __ATOMIC_RELEASE);
						}
						__sync_fetch_and_add(&g_total_scanned_pages, pages);
					}
					clock_gettime(CLOCK_MONOTONIC, &t3);
					dist_time_ns += (t3.tv_sec - t2.tv_sec) * 1000000000UL +
							(t3.tv_nsec - t2.tv_nsec);
				} while (args.walk_end < chunk_end);

				chunk_start = chunk_end;
			}
		}

		clock_gettime(CLOCK_MONOTONIC, &iter_end);

		/* Store this scanner's dirty count */
		ctx->dirty_count = my_dirty_pages;

		/* Synchronize with other pre-scanners */
		pthread_mutex_lock(&g_scanner_mutex);
		g_scanners_iter_done++;
		if (g_scanners_iter_done == clone_cfg.num_pre_scanners) {
			/* Last pre-scanner to finish - calculate total and reset */
			int s;

			g_total_dirty_pages = 0;
			for (s = 0; s < clone_cfg.num_pre_scanners; s++)
				g_total_dirty_pages += scanners[s].dirty_count;
			g_scanners_iter_done = 0;
			pthread_cond_broadcast(&g_scanner_cond);
		} else {
			/* Wait for other scanner */
			pthread_cond_wait(&g_scanner_cond, &g_scanner_mutex);
		}
		pthread_mutex_unlock(&g_scanner_mutex);

		/* Log timing - each scanner logs its own stats */
		{
			long iter_ms = (iter_end.tv_sec - iter_start.tv_sec) * 1000 +
				       (iter_end.tv_nsec - iter_start.tv_nsec) / 1000000;
			pr_debug("Scanner[%d] iter=%u: pages=%lu regions=%lu scan=%lu ms dist=%lu ms total=%ld ms\n",
			       scanner_id, iteration, my_dirty_pages, num_regions,
			       scan_time_ns / 1000000, dist_time_ns / 1000000, iter_ms);
		}
		/* Scanner 0 also logs combined stats */
		if (scanner_id == 0) {
			pr_debug("Scanner: iter=%u, %lu total pages\n",
			       iteration, g_total_dirty_pages);
		}

		/* Check convergence - pre-scanners check the combined total */
		if (g_total_dirty_pages < CLONE_DIRTY_SCAN_FREEZE_THRESHOLD) {
			if (scanner_id == 0) {
				pr_debug("Scanner: %lu pages < %d threshold, will request freeze after queue drain\n",
				       g_total_dirty_pages, CLONE_DIRTY_SCAN_FREEZE_THRESHOLD);
			}
			break;
		}

		/* Check max iterations limit */
		if (CLONE_PRE_SCAN_MAX_ITERATIONS > 0 && iteration >= CLONE_PRE_SCAN_MAX_ITERATIONS) {
			if (scanner_id == 0) {
				pr_debug("Scanner: max iterations (%u) reached, will request freeze after queue drain\n", iteration);
			}
			break;
		}

		usleep(CLONE_USLEEP_1MS);
	}

	/* Wait for P3 senders to drain the queue before requesting freeze */
	if (scanner_id == 0) {
		unsigned long head, tail;
		struct timespec drain_start, drain_end;
		long drain_ms;

		clock_gettime(CLOCK_MONOTONIC, &drain_start);
		pr_debug("Scanner: waiting for queue drain before freeze...\n");

		while (1) {
			head = __atomic_load_n(&g_conv_head, __ATOMIC_ACQUIRE);
			tail = __atomic_load_n(&g_conv_tail, __ATOMIC_RELAXED);
			if (tail >= head)
				break;
			usleep(CLONE_USLEEP_1MS);
		}

		clock_gettime(CLOCK_MONOTONIC, &drain_end);
		drain_ms = (drain_end.tv_sec - drain_start.tv_sec) * 1000 +
			   (drain_end.tv_nsec - drain_start.tv_nsec) / 1000000;
		pr_debug("Scanner: queue drained in %ld ms, requesting freeze\n", drain_ms);
		g_last_scan_flag = true;
	}

wait_for_freeze:

	/* Wait for freeze signal from main thread */
	if (scanner_id == 0) {
		pr_debug("Scanner: waiting for freeze signal...\n");
	}
	while (!__atomic_load_n(&g_scanner_freeze_signal, __ATOMIC_ACQUIRE)) {
		usleep(CLONE_USLEEP_1MS);
	}

	/* Final scan after freeze - each scanner handles its portion */
	{
		unsigned long final_dirty = 0;
		/* Continue round-robin from where we left off */
		struct timespec fs_start, fs_end;

		clock_gettime(CLOCK_MONOTONIC, &fs_start);
		if (scanner_id == 0) {
			pr_debug("Scanner: final scan (frozen)\n");
		}

		list_for_each_entry(lve, lazy_vmas, list) {
			struct pm_scan_arg args;
			long regs_len;
			unsigned long vma_size = lve->end - lve->start;
			unsigned long total_pages = vma_size / PAGE_SIZE;
			unsigned long pages_per_scanner = total_pages / clone_cfg.num_scanners;
			unsigned long my_start, my_end;

			my_start = lve->start + (scanner_id * pages_per_scanner * PAGE_SIZE);
			if (scanner_id == clone_cfg.num_scanners - 1)
				my_end = lve->end;
			else
				my_end = my_start + (pages_per_scanner * PAGE_SIZE);

			if (my_end <= my_start)
				continue;

			/* No range chunking needed - process is frozen */
			memset(&args, 0, sizeof(args));
			args.size = sizeof(args);
			args.flags = 0;  /* No WP_MATCHING - just read dirty state */
			args.start = my_start;
			args.end = my_end;
			args.walk_end = my_start;
			args.vec = (u64)(unsigned long)regs;
			args.vec_len = max_regs;
			args.max_pages = CLONE_PAGEMAP_SCAN_MAX_PAGES_ITER1;
			args.category_anyof_mask = PAGE_IS_WRITTEN;
			args.return_mask = PAGE_IS_WRITTEN;

			do {
				int i;
				args.start = args.walk_end;

				regs_len = ioctl(ctx->pagemap_fd, PAGEMAP_SCAN, &args);
				if (regs_len < 0)
					break;
				if (regs_len == 0)
					break;

				for (i = 0; i < regs_len; i++) {
					struct dirty_region_entry *entry;
					unsigned long pages;

					pages = (regs[i].end - regs[i].start) / PAGE_SIZE;
					final_dirty += pages;

					entry = xmalloc(sizeof(*entry));
					BUG_ON(!entry);
					entry->start = regs[i].start;
					entry->end = regs[i].end;
					entry->dst_id = lve->dst_id;
					entry->source_pid = g_scanner_source_pid;

					{
						unsigned long slot = __atomic_fetch_add(&g_conv_head, 1, __ATOMIC_RELAXED);
						BUG_ON(slot >= CONV_QUEUE_CAP);
						__atomic_store_n(&g_conv_slots[slot], entry, __ATOMIC_RELEASE);
					}
					__sync_fetch_and_add(&g_total_scanned_pages, pages);
				}
			} while (args.walk_end < my_end);
		}

		clock_gettime(CLOCK_MONOTONIC, &fs_end);

		/* Store final dirty count for this scanner */
		ctx->dirty_count = final_dirty;

		/* Synchronize final scan completion */
		pthread_mutex_lock(&g_scanner_mutex);
		g_scanners_iter_done++;
		if (g_scanners_iter_done == clone_cfg.num_scanners) {
			unsigned long total_final = 0;
			long fs_ms;
			int s;

			for (s = 0; s < clone_cfg.num_scanners; s++)
				total_final += scanners[s].dirty_count;
			fs_ms = (fs_end.tv_sec - fs_start.tv_sec) * 1000 +
				(fs_end.tv_nsec - fs_start.tv_nsec) / 1000000;
			pr_debug("Scanner: PAGEMAP_SCAN done: %lu dirty pages found in %ld ms\n",
			       total_final, fs_ms);
			g_scanners_iter_done = 0;
			pthread_cond_broadcast(&g_scanner_cond);
		} else {
			pthread_cond_wait(&g_scanner_cond, &g_scanner_mutex);
		}
		pthread_mutex_unlock(&g_scanner_mutex);
	}

	xfree(regs);

	if (ctx->pagemap_fd >= 0) {
		close(ctx->pagemap_fd);
		ctx->pagemap_fd = -1;
	}

out:
	clock_gettime(CLOCK_MONOTONIC, &t_end);
	{
		long elapsed_ms = (t_end.tv_sec - t_start.tv_sec) * 1000 +
				  (t_end.tv_nsec - t_start.tv_nsec) / 1000000;
		pr_debug("Scanner[%d] done: %u iterations, %ld ms\n",
		       scanner_id, iteration, elapsed_ms);
	}

	/* Mark this scanner as finished */
	ctx->finished = true;

	/* Last scanner to finish signals completion to senders */
	pthread_mutex_lock(&g_scanner_mutex);
	{
		bool all_done = true;
		int s;

		for (s = 0; s < clone_cfg.num_scanners; s++) {
			if (!scanners[s].finished) {
				all_done = false;
				break;
			}
		}
		if (all_done) {
			unsigned long total_pages;
			struct timespec now;
			long from_freeze_ms;

			clock_gettime(CLOCK_MONOTONIC, &now);
			from_freeze_ms = (now.tv_sec - g_freeze_signal_time.tv_sec) * 1000 +
					 (now.tv_nsec - g_freeze_signal_time.tv_nsec) / 1000000;
			pr_debug("Scanner: all scanners done, %ld ms from freeze signal\n", from_freeze_ms);

			total_pages = __atomic_load_n(&g_total_scanned_pages, __ATOMIC_RELAXED);
			pr_debug("MPMC queue: %lu total scanned pages, %lu entries\n",
			       total_pages, __atomic_load_n(&g_conv_head, __ATOMIC_RELAXED));

			__atomic_store_n(&g_scan_complete, true, __ATOMIC_RELEASE);
		}
	}
	pthread_mutex_unlock(&g_scanner_mutex);

	return NULL;
}

int clone_start_scanner_thread(pid_t source_pid)
{
	int i;
	struct list_head *lazy_vmas = clone_mem_get_lazy_vmas();
	struct lazy_vma_entry *lve;
	unsigned int lve_count = 0;

	list_for_each_entry(lve, lazy_vmas, list) {
		pr_debug("VMA_TRACE: phase=SCANNER_START_LIST idx=%u vma=0x%" PRIx64 "-0x%" PRIx64
		       " pages=%lu dst_id=%" PRIu64 "\n",
		       lve_count, lve->start, lve->end, lve->total_pages,
		       (uint64_t)lve->dst_id);
		lve_count++;
	}
	pr_debug("VMA_TRACE: phase=SCANNER_START total_lazy_vmas=%u pid=%d\n",
	       lve_count, source_pid);

	g_scanner_source_pid = source_pid;
	g_scan_complete = false;
	g_scanner_freeze_signal = false;
	g_scanners_iter_done = 0;
	g_total_dirty_pages = 0;

	/* Reset verification counters */
	g_total_scanned_pages = 0;
	g_total_sent_pages = 0;
	g_vma_vanished_skipped_pages = 0;

	/* Initialize and start scanner threads */
	for (i = 0; i < clone_cfg.num_scanners; i++) {
		scanners[i].id = i;
		scanners[i].pagemap_fd = -1;
		scanners[i].dirty_count = 0;
		scanners[i].finished = false;

		if (pthread_create(&scanners[i].thread, NULL,
				   dirty_scanner_thread, &scanners[i])) {
			pr_perror("Failed to create scanner thread %d", i);
			return -1;
		}
	}

	pr_info("Started %d scanner threads for pid %d\n", clone_cfg.num_scanners, source_pid);
	return 0;
}

void clone_wait_scanner_thread(void)
{
	int i;

	for (i = 0; i < clone_cfg.num_scanners; i++) {
		if (scanners[i].thread) {
			pthread_join(scanners[i].thread, NULL);
			scanners[i].thread = 0;
			pr_debug("Scanner thread %d joined\n", i);
		}
	}
	/* Senders drain their own queues during normal exit */
}

void clone_set_new_vma_ranges(unsigned long *ranges, unsigned int nr_ranges)
{
	g_new_vma_ranges = ranges;
	g_nr_new_vma_ranges = nr_ranges;
	__sync_synchronize();  /* Memory barrier for ARM */
	pr_info("Set %u new VMA ranges for P3 threads to send\n", nr_ranges);
}

void clone_free_new_vma_ranges(void)
{
	if (g_new_vma_ranges) {
		xfree(g_new_vma_ranges);
		g_new_vma_ranges = NULL;
		g_nr_new_vma_ranges = 0;
	}
}

/*
 * Thread-local send buffer (header + compressed-size + compressed-data),
 * sized for the max batch so it's allocated once per thread and reused.
 */
#define CLONE_SEND_BUF_SIZE	(sizeof(struct page_server_iov) + sizeof(int) + \
				 LZ4_COMPRESSBOUND(CLONE_BATCH_SIZE))
static __thread char *tls_send_buf;

/*
 * Thread-local compression counters. Snapshot at phase boundaries to report
 * per-phase compression ratio without atomics on the hot path.
 */
static __thread unsigned long tls_compress_in_bytes;
static __thread unsigned long tls_compress_out_bytes;
static __thread unsigned long tls_total_sent_pages;

/*
 * Send a batch of pages with LZ4 compression.
 * Protocol: header (PS_IOV_ADD_F_COMPRESS) + compressed_size + compressed_data
 * Header contains nr_pages and base_vaddr.
 *
 * acceleration: LZ4_compress_fast acceleration. 1 matches LZ4_compress_default
 * (best ratio). Larger values trade ratio for CPU. All current callers pass 1;
 * larger values were measured to regress total P3 wall-clock (see the note in
 * send_dirty_slices()).
 */
int send_pages_batch_compressed(struct tls_conn *tls, int sk,
				const void *data, int nr_pages, u64 dst_id,
				unsigned long base_vaddr,
				int acceleration)
{
	int max_compressed = LZ4_compressBound(nr_pages * PAGE_SIZE);
	int total_uncompressed = nr_pages * PAGE_SIZE;
	char *send_buf;
	struct page_server_iov *pi;
	int *compressed_size;
	char *compressed_data;
	int total_len, ret;

	if (!tls_send_buf) {
		tls_send_buf = xmalloc(CLONE_SEND_BUF_SIZE);
		BUG_ON(!tls_send_buf);
	}
	send_buf = tls_send_buf;

	pi = (struct page_server_iov *)send_buf;
	compressed_size = (int *)(send_buf + sizeof(*pi));
	compressed_data = send_buf + sizeof(*pi) + sizeof(int);

	/* Compress entire batch */
	*compressed_size = LZ4_compress_fast(data, compressed_data,
					     total_uncompressed, max_compressed,
					     acceleration);
	if (*compressed_size <= 0) {
		pr_err("LZ4 compression failed for batch at %lx (%d pages)\n",
		       base_vaddr, nr_pages);
		return -1;
	}

	/* Thread-local counters — flushed to globals once at thread exit */
	tls_compress_in_bytes += total_uncompressed;
	tls_compress_out_bytes += *compressed_size;

	pr_debug("Compressed batch at %lx: %d pages, %d -> %d bytes (%.1f%%)\n",
		 base_vaddr, nr_pages, total_uncompressed, *compressed_size,
		 (float)(*compressed_size) * 100 / total_uncompressed);

	/* Fill header - use nr_pages to indicate batch size */
	pi->cmd = encode_ps_cmd(PS_IOV_ADD_F_COMPRESS, PE_PRESENT);
	pi->nr_pages = nr_pages;
	pi->vaddr = base_vaddr;
	pi->dst_id = dst_id;

	/* Single send: header + size + compressed data */
	total_len = sizeof(*pi) + sizeof(int) + *compressed_size;
	if (tls)
		ret = tls_conn_send_all(tls, send_buf, total_len, 0);
	else
		ret = page_server_send_raw(sk, send_buf, total_len, 0);

	if (ret != total_len) {
		pr_perror("Failed to send compressed batch (sent %d/%d)", ret, total_len);
		return -1;
	}

	return 0;
}

/*
 * Thread-local page read buffer, sized for the max batch.
 * Allocated once per thread and reused across all process_vm_readv calls.
 */
static __thread char *tls_read_buf;

static inline char *clone_get_read_buf(void)
{
	if (!tls_read_buf) {
		tls_read_buf = xmalloc(CLONE_BATCH_SIZE);
		BUG_ON(!tls_read_buf);
	}
	return tls_read_buf;
}

/*
 * Read and send a batch of contiguous pages from source process.
 * Returns number of pages actually sent, or -1 on error.
 */
static int send_lazy_vma_pages_batch(struct tls_conn *tls, int sk,
				     struct lazy_vma_entry *lve,
				     unsigned long base_vaddr, int max_pages,
				     u64 dst_id, pid_t source_pid)
{
	void *buffer;
	struct iovec local_iov, remote_iov;
	int nr_pages = 0;
	unsigned long vaddr;
	int ret, i;

	/* Find contiguous run of pages from base_vaddr */
	for (i = 0; i < max_pages; i++) {
		vaddr = base_vaddr + i * PAGE_SIZE;
		if (vaddr >= lve->end)
			break;
		nr_pages++;
	}

	if (nr_pages == 0)
		return 0;

	buffer = clone_get_read_buf();

	/* Single process_vm_readv for all pages */
	local_iov.iov_base = buffer;
	local_iov.iov_len = nr_pages * PAGE_SIZE;
	remote_iov.iov_base = (void *)base_vaddr;
	remote_iov.iov_len = nr_pages * PAGE_SIZE;

	ret = process_vm_readv(source_pid, &local_iov, 1, &remote_iov, 1, 0);
	if (ret != (ssize_t)(nr_pages * PAGE_SIZE)) {
		/*
		 * EFAULT / ESRCH / ENOMEM mean the VMA (or part of it) is
		 * no longer mapped in the source — typically because the
		 * source process is in Phase 2 and did a munmap between
		 * VMA enumeration and the read. The REMOVE event is only
		 * observed by the target's lazy-pages daemon, so the dumper
		 * has no other signal; process_vm_readv's errno IS the
		 * detection mechanism. Log and skip.
		 *
		 * NOTE: we do NOT bump g_vma_vanished_skipped_pages here.
		 * This path is the *initial bulk* walk — those pages were
		 * never counted into g_total_scanned_pages (that counter
		 * only tracks dirty-region re-sends via the scanner). A
		 * skip here is a no-op for the scanned/sent balance.
		 *
		 * Other errors (EPERM, EINVAL, E2BIG, etc.) are genuine
		 * failures and still return -1.
		 */
		if (ret < 0 && clone_errno_is_vma_gone(errno)) {
			pr_debug("clone-bulk: VMA vanished at %lx (pid %d, %d pages, errno=%d): skip (bulk path)\n",
				 base_vaddr, source_pid, nr_pages, errno);
			/* Record for Phase 3 remap detection (fallback to UFFD events) */
			clone_record_unmapped_range(base_vaddr, (unsigned long)nr_pages * PAGE_SIZE);
			return 0;
		}
		pr_perror("Failed to read %d pages at %lx from pid %d (got %d)",
			  nr_pages, base_vaddr, source_pid, (int)ret);
		return -1;
	}

	/*
	 * Pre-freeze bulk transfer: we have CPU time to spare because the
	 * process is still running; use best-ratio LZ4 to save network.
	 */
	ret = send_pages_batch_compressed(tls, sk, buffer, nr_pages, dst_id,
					  base_vaddr, 1);
	if (ret < 0)
		return -1;

	return nr_pages;
}

/*
 * A slice of a dirty region: a contiguous [start, start + nr_pages*PAGE)
 * sub-range of one dirty_region_entry. A batch may mix many whole small
 * regions with a sliced portion of a larger one.
 */
struct dirty_slice {
	unsigned long start;
	int nr_pages;
	u64 dst_id;
};

/*
 * Read nr_slices ranges from the source process in one process_vm_readv,
 * then send each slice via the existing compressed path on the
 * corresponding buffer offset.
 *
 * Caller guarantees:
 *   - all slices share the same source_pid (one queue == one source today)
 *   - sum of nr_pages across slices <= CLONE_BATCH_PAGES (tls_read_buf is
 *     sized for CLONE_BATCH_SIZE)
 *   - nr_slices <= CLONE_BATCH_PAGES (and thus well below IOV_MAX)
 *
 * On short/failed readv we recurse per slice so one bad range (e.g. an
 * unmap-during-scan race on a single page) doesn't drop the whole batch.
 *
 * Convergence / post-freeze path. Keep acceleration=1. Experiment:
 * acceleration=99 was tried here to cut LZ4 CPU (was 51% of P3 thread
 * time). It regressed the total P3 wall-clock 2.3s -> 4.8s: ratio dropped
 * from ~25% to ~53-84% on this workload (dirty pages still compress),
 * and the extra wire bytes shifted the bottleneck into tcp_sendmsg +
 * skb_page_frag_refill, with atomic CAS contention roughly doubling.
 *
 * Returns total pages sent, or -1 on a fatal send error.
 */
static int send_dirty_slices(struct p3_thread_ctx *ctx,
			     pid_t source_pid,
			     const struct dirty_slice *slices,
			     int nr_slices)
{
	void *buffer = clone_get_read_buf();
	struct iovec local_iov;
	struct iovec remote_iov[CLONE_BATCH_PAGES];
	unsigned long total_bytes = 0;
	int total_sent = 0;
	ssize_t ret;
	int i;

	if (nr_slices <= 0)
		return 0;

	for (i = 0; i < nr_slices; i++) {
		unsigned long len = (unsigned long)slices[i].nr_pages * PAGE_SIZE;

		remote_iov[i].iov_base = (void *)slices[i].start;
		remote_iov[i].iov_len = len;
		total_bytes += len;
	}

	local_iov.iov_base = buffer;
	local_iov.iov_len = total_bytes;

	ret = process_vm_readv(source_pid, &local_iov, 1,
			       remote_iov, nr_slices, 0);
	if (ret == (ssize_t)total_bytes) {
		/* Fast path: whole batch readable in one syscall. */
		unsigned long offset = 0;
		for (i = 0; i < nr_slices; i++) {
			int nr_pages = slices[i].nr_pages;
			int srv;

			srv = send_pages_batch_compressed(ctx->tls, ctx->socket,
							  (char *)buffer + offset,
							  nr_pages, slices[i].dst_id,
							  slices[i].start, 1);
			if (srv < 0)
				return -1;
			total_sent += nr_pages;
			ctx->pages_sent += nr_pages;
			tls_total_sent_pages += nr_pages;
			offset += (unsigned long)nr_pages * PAGE_SIZE;
		}
		return total_sent;
	}

	/*
	 * Slow path: the multi-iov readv failed. One or more slices
	 * have a VMA that vanished between scanner enumeration and our
	 * read. Retry each slice individually so a single bad range
	 * doesn't drop the whole batch.
	 *
	 * A non-vma-gone errno on the single-slice retry is a real
	 * error and aborts the batch.
	 */
	if (!(ret < 0 && clone_errno_is_vma_gone(errno))) {
		pr_perror("send_dirty_slices: unexpected process_vm_readv failure (ret=%zd, %d slices)",
			  ret, nr_slices);
		return -1;
	}

	for (i = 0; i < nr_slices; i++) {
		int nr_pages = slices[i].nr_pages;
		unsigned long len = (unsigned long)nr_pages * PAGE_SIZE;
		struct iovec lone_local, lone_remote;
		int srv;
		ssize_t r;

		lone_local.iov_base = buffer;
		lone_local.iov_len = len;
		lone_remote.iov_base = (void *)slices[i].start;
		lone_remote.iov_len = len;

		r = process_vm_readv(source_pid, &lone_local, 1, &lone_remote, 1, 0);
		if (r != (ssize_t)len) {
			if (r < 0 && clone_errno_is_vma_gone(errno)) {
				__sync_fetch_and_add(&g_vma_vanished_skipped_pages,
						     nr_pages);
				pr_debug("send_dirty_slices: slice %d at %lx vanished (%d pages, errno=%d): skip\n",
					 i, slices[i].start, nr_pages, errno);
				/* Record for Phase 3 remap detection (fallback to UFFD events) */
				clone_record_unmapped_range(slices[i].start, len);
				continue;
			}
			pr_perror("send_dirty_slices: slice %d at %lx read failed (ret=%zd)",
				  i, slices[i].start, r);
			return -1;
		}

		srv = send_pages_batch_compressed(ctx->tls, ctx->socket,
						  buffer, nr_pages,
						  slices[i].dst_id,
						  slices[i].start, 1);
		if (srv < 0)
			return -1;

		total_sent += nr_pages;
		ctx->pages_sent += nr_pages;
		tls_total_sent_pages += nr_pages;
	}

	return total_sent;
}

/*
 * Send all pages from new VMAs detected in Phase 3.
 * New VMAs need ALL their pages sent (not just dirty), split among threads.
 */
static unsigned long send_new_vma_pages(struct p3_thread_ctx *ctx)
{
	unsigned int i;
	unsigned long total_sent = 0;
	unsigned int ranges_per_thread, my_start_idx, my_end_idx;
	void *buffer;
	struct iovec local_iov, remote_iov;
	int thread_id = ctx->thread_id;

	if (!g_new_vma_ranges || g_nr_new_vma_ranges == 0)
		return 0;

	/* Split ranges among threads */
	ranges_per_thread = (g_nr_new_vma_ranges + clone_cfg.num_p3_threads - 1) / clone_cfg.num_p3_threads;
	my_start_idx = thread_id * ranges_per_thread;
	my_end_idx = my_start_idx + ranges_per_thread;
	if (my_end_idx > g_nr_new_vma_ranges)
		my_end_idx = g_nr_new_vma_ranges;

	if (my_start_idx >= g_nr_new_vma_ranges)
		return 0;  /* No ranges for this thread */

	pr_info("P3[%d] sending new VMA pages: ranges %u-%u of %u\n",
		thread_id, my_start_idx, my_end_idx, g_nr_new_vma_ranges);

	buffer = clone_get_read_buf();

	for (i = my_start_idx; i < my_end_idx; i++) {
		unsigned long start = g_new_vma_ranges[i * 2];
		unsigned long len = g_new_vma_ranges[i * 2 + 1];
		unsigned long vaddr;

		pr_debug("P3[%d] new VMA %lx-%lx (%lu pages)\n",
			 thread_id, start, start + len, len / PAGE_SIZE);
		pr_debug("VMA_TRACE: phase=PHASE3_SEND_NEW thread_id=%d range=0x%lx-0x%lx pages=%lu\n",
		       thread_id, start, start + len, len / PAGE_SIZE);

		for (vaddr = start; vaddr < start + len; ) {
			int batch_pages = (start + len - vaddr) / PAGE_SIZE;
			ssize_t ret;

			if (batch_pages > CLONE_BATCH_PAGES)
				batch_pages = CLONE_BATCH_PAGES;

			/* Read pages from source process */
			local_iov.iov_base = buffer;
			local_iov.iov_len = batch_pages * PAGE_SIZE;
			remote_iov.iov_base = (void *)vaddr;
			remote_iov.iov_len = batch_pages * PAGE_SIZE;

			ret = process_vm_readv(ctx->source_pid, &local_iov, 1,
					       &remote_iov, 1, 0);
			if (ret != (ssize_t)(batch_pages * PAGE_SIZE)) {
				pr_warn("P3[%d] failed to read new VMA pages at %lx: %s\n",
					thread_id, vaddr, strerror(errno));
				vaddr += batch_pages * PAGE_SIZE;
				continue;
			}

			/*
			 * New VMAs only surface during/after freeze. Keep
			 * acceleration=1 for the same reason as
			 * send_dirty_slices: acceleration=99 regressed
			 * P3 wall-clock 2.3s -> 4.8s by shifting the
			 * bottleneck to tcp_sendmsg.
			 */
			ret = send_pages_batch_compressed(ctx->tls, ctx->socket,
							  buffer, batch_pages,
							  ctx->dst_id, vaddr, 1);
			if (ret < 0) {
				pr_err("P3[%d] failed to send new VMA pages at %lx, aborting\n",
				       thread_id, vaddr);
				return total_sent;  /* Abort - socket is likely broken */
			}

			total_sent += batch_pages;
			ctx->pages_sent += batch_pages;
			vaddr += batch_pages * PAGE_SIZE;
		}
	}

	pr_info("P3[%d] sent %lu pages from new VMAs\n", thread_id, total_sent);
	return total_sent;
}

/*
 * P3 bulk sender thread - sends regular pages in batches.
 * Uses work-stealing: threads pull chunks from a shared work queue.
 * After bulk transfer, transitions to iterative dirty scanning until convergence.
 */
static void *p3_bulk_sender_thread(void *arg)
{
	struct p3_thread_ctx *ctx = (struct p3_thread_ctx *)arg;
	unsigned long total_sent = 0;
	struct timespec t_start, t_end;
	int thread_id = ctx->thread_id;
	int chunks_processed = 0;

	pr_info("P3[%d] bulk sender thread started (batch=%d pages)\n",
		thread_id, CLONE_BATCH_PAGES);
	pr_debug("DEBUG_THREAD: P3 sender[%d] STARTED socket=%d dst_id=%lu\n",
	       thread_id, ctx->socket, (unsigned long)ctx->dst_id);
	clock_gettime(CLOCK_MONOTONIC, &t_start);

	/* Iteration 0: bulk transfer with work-stealing */
	{
		struct timespec bulk_start, bulk_end;
		long bulk_elapsed_ms;
		struct bulk_work_item *work;
		unsigned long bulk_in_start = tls_compress_in_bytes;
		unsigned long bulk_out_start = tls_compress_out_bytes;
		unsigned long bulk_in_bytes, bulk_out_bytes;
		float bulk_ratio_pct = 0.0f;

		clock_gettime(CLOCK_MONOTONIC, &bulk_start);

		/*
		 * Only clone_cfg.num_p3_threads_bulk threads participate in bulk transfer.
		 * Other threads skip to phase 2 (dirty scanning) where all threads
		 * are needed to keep up with parallel scanners.
		 */
		if (thread_id < clone_cfg.num_p3_threads_bulk) {
#ifdef CLONE_P3_SENDER_CPU
			pin_to_cpu(CLONE_P3_SENDER_CPU);
#endif
			pr_debug("P3[%d]: Starting bulk transfer (work-stealing)\n", thread_id);

			/* Pull work items from shared queue until exhausted */
			while ((work = get_next_work_item()) != NULL) {
				unsigned long vaddr;

				for (vaddr = work->start; vaddr < work->end; ) {
					unsigned long next_bound = (vaddr + CLONE_BATCH_SIZE) & CLONE_BATCH_ALIGN_MASK;
					unsigned long batch_end = (next_bound < work->end) ? next_bound : work->end;
					int batch_pages = (batch_end - vaddr) / PAGE_SIZE;
					int sent;

					sent = send_lazy_vma_pages_batch(
						ctx->tls, ctx->socket, work->lve,
						vaddr, batch_pages,
						ctx->dst_id, ctx->source_pid);

					if (sent < 0) {
						/*
						 * Real I/O / socket error. The dump is
						 * unrecoverable; flag the per-thread
						 * error for clone_wait_p3_threads() and
						 * stop this sender cleanly. No BUG() —
						 * that would leave sibling P3 threads
						 * running and produce a torn abort.
						 */
						pr_err("P3[%d]: Failed to send batch at %lx — marking dump as failed\n",
						       thread_id, vaddr);
						ctx->error = true;
						goto p3_sender_exit;
					}

					/*
					 * sent == 0 means the VMA vanished between
					 * enumeration and read (munmap race) — soft
					 * error, skip this batch and continue.
					 */
					total_sent += sent;
					vaddr += batch_pages * PAGE_SIZE;
				}
				chunks_processed++;
			}
		} else {
			pr_debug("P3[%d]: Skipping bulk (idle until phase 2)\n", thread_id);
		}

		clock_gettime(CLOCK_MONOTONIC, &bulk_end);
		bulk_elapsed_ms = (bulk_end.tv_sec - bulk_start.tv_sec) * 1000 +
				  (bulk_end.tv_nsec - bulk_start.tv_nsec) / 1000000;

		bulk_in_bytes = tls_compress_in_bytes - bulk_in_start;
		bulk_out_bytes = tls_compress_out_bytes - bulk_out_start;
		if (bulk_in_bytes > 0)
			bulk_ratio_pct = (float)bulk_out_bytes * 100.0f / bulk_in_bytes;
		pr_debug("P3[%d] TIMING: Bulk transfer done: %lu pages, %d chunks in %ld ms "
		       "(compress: %lu -> %lu bytes, ratio=%.1f%%)\n",
		       thread_id, total_sent, chunks_processed, bulk_elapsed_ms,
		       bulk_in_bytes, bulk_out_bytes, bulk_ratio_pct);

		/* Signal scanner that this thread's bulk transfer is complete */
		__atomic_fetch_add(&g_bulk_transfer_done_count, 1, __ATOMIC_RELEASE);

#ifdef CLONE_P3_SENDER_CPU
		/* Unpin CPU for phase 2 - all threads need full CPU access */
		if (thread_id < clone_cfg.num_p3_threads_bulk)
			unpin_cpu();
#endif
	}

	/* Phase 2: consume dirty regions from scanner queue */
	{
		struct timespec loop_start, loop_end, p3_start, scan_done_time;
		long loop_elapsed_ms;
		unsigned long loop_total_pages = 0;
		unsigned long regions_processed = 0;
		unsigned long slices_sent = 0;
		unsigned long packed_batches = 0;
		unsigned long p3_pages = 0;
		unsigned long pages_before_scan_done = 0;
		bool p3_started = false;
		bool scan_done_logged = false;
		unsigned long cursor_vaddr = 0;
		unsigned long queue_in_start;
		unsigned long queue_out_start;
		unsigned long queue_in_bytes, queue_out_bytes;
		float queue_ratio_pct = 0.0f;

		if (!clone_cfg.pre_scan) {
			/* Without pre-scan, wait for freeze signal before consuming queue */
			while (!__atomic_load_n(&g_scanner_freeze_signal, __ATOMIC_ACQUIRE)) {
				usleep(CLONE_USLEEP_1MS);
			}
		}
		/* With pre-scan, start consuming immediately - don't wait for freeze */

		clock_gettime(CLOCK_MONOTONIC, &loop_start);
		queue_in_start = tls_compress_in_bytes;
		queue_out_start = tls_compress_out_bytes;

		/*
		 * MPMC consumer: CAS-claim one entry at a time from the
		 * shared convergence queue. Pack entries into 64-page
		 * batches for readv + compress + send.
		 */
		{
			struct dirty_region_entry *region = NULL;

			while (1) {
				struct dirty_slice slices[CLONE_BATCH_PAGES];
				int nr_slices = 0;
				int pages_left = CLONE_BATCH_PAGES;
				int sent;

				if (!p3_started && g_last_scan_flag) {
					p3_started = true;
					clock_gettime(CLOCK_MONOTONIC, &p3_start);
				}
				if (!scan_done_logged && clone_is_scan_complete()) {
					scan_done_logged = true;
					pages_before_scan_done = p3_pages;
					clock_gettime(CLOCK_MONOTONIC, &scan_done_time);
				}

				if (!region) {
					region = conv_queue_pop();
					if (!region) {
						if (clone_is_scan_complete() &&
						    __atomic_load_n(&g_conv_tail, __ATOMIC_RELAXED) >=
						    __atomic_load_n(&g_conv_head, __ATOMIC_ACQUIRE))
							break;
						usleep(CLONE_USLEEP_100US);
						continue;
					}
					cursor_vaddr = region->start;
				}

				while (pages_left > 0 && region) {
					int have = (int)((region->end - cursor_vaddr) / PAGE_SIZE);
					int take = have < pages_left ? have : pages_left;

					slices[nr_slices].start = cursor_vaddr;
					slices[nr_slices].nr_pages = take;
					slices[nr_slices].dst_id = region->dst_id;
					nr_slices++;
					cursor_vaddr += (unsigned long)take * PAGE_SIZE;
					pages_left -= take;

					if (cursor_vaddr == region->end) {
						regions_processed++;
						xfree(region);
						region = conv_queue_pop();
						if (region)
							cursor_vaddr = region->start;
					}
				}

				if (nr_slices == 0)
					continue;

				sent = send_dirty_slices(ctx, g_scanner_source_pid,
							 slices, nr_slices);
				if (sent < 0) {
					/* Real I/O error; abort this sender so
					 * clone_wait_p3_threads flags the dump. */
					pr_err("P3[%d]: send_dirty_slices failed — aborting\n",
					       thread_id);
					ctx->error = true;
					goto p3_sender_exit;
				}
				/* sent == 0 is legitimate: every slice in the
				 * batch had its VMA vanish (counted via
				 * g_vma_vanished_skipped_pages). */
				loop_total_pages += sent;
				slices_sent += nr_slices;
				packed_batches++;
				if (p3_started)
					p3_pages += sent;
			}

			if (region)
				xfree(region);
		}

		clock_gettime(CLOCK_MONOTONIC, &loop_end);

		/* Capture scan_done_time if loop exited with scan complete but flag not yet set */
		if (!scan_done_logged && clone_is_scan_complete()) {
			scan_done_logged = true;
			pages_before_scan_done = p3_pages;
			scan_done_time = loop_end;
		}

		loop_elapsed_ms = (loop_end.tv_sec - loop_start.tv_sec) * 1000 +
				  (loop_end.tv_nsec - loop_start.tv_nsec) / 1000000;

		/* Print Phase 3 specific timing */
		if (p3_started) {
			long p3_total_ms = (loop_end.tv_sec - p3_start.tv_sec) * 1000 +
					   (loop_end.tv_nsec - p3_start.tv_nsec) / 1000000;
			long send_during_scan_ms = 0;
			long send_after_scan_ms = 0;

			if (scan_done_logged) {
				send_during_scan_ms = (scan_done_time.tv_sec - p3_start.tv_sec) * 1000 +
						      (scan_done_time.tv_nsec - p3_start.tv_nsec) / 1000000;
				send_after_scan_ms = (loop_end.tv_sec - scan_done_time.tv_sec) * 1000 +
						     (loop_end.tv_nsec - scan_done_time.tv_nsec) / 1000000;
			}
			pr_debug("P3[%d] TIMING P3: total=%ld ms (during_scan=%ld ms [%lu pages] + after_scan=%ld ms [%lu pages])\n",
			       thread_id, p3_total_ms, send_during_scan_ms, pages_before_scan_done,
			       send_after_scan_ms, p3_pages - pages_before_scan_done);
		}
		queue_in_bytes = tls_compress_in_bytes - queue_in_start;
		queue_out_bytes = tls_compress_out_bytes - queue_out_start;
		if (queue_in_bytes > 0)
			queue_ratio_pct = (float)queue_out_bytes * 100.0f / queue_in_bytes;
		{
			float avg_slices = 0.0f;
			float avg_pages = 0.0f;
			if (packed_batches > 0) {
				avg_slices = (float)slices_sent / packed_batches;
				avg_pages = (float)loop_total_pages / packed_batches;
			}
			pr_debug("P3[%d] TIMING: Queue consumption done: "
			       "%lu regions, %lu pages in %ld ms "
			       "(packed_batches=%lu slices=%lu "
			       "avg_slices/batch=%.2f avg_pages/batch=%.2f) "
			       "(compress: %lu -> %lu bytes, ratio=%.1f%%)\n",
			       thread_id, regions_processed,
			       loop_total_pages, loop_elapsed_ms,
			       packed_batches, slices_sent,
			       avg_slices, avg_pages,
			       queue_in_bytes, queue_out_bytes, queue_ratio_pct);
		}
	}

	/* Final: send pages from new VMAs detected in Phase 3 */
	{
		struct timespec fs_start, fs_end;
		long fs_elapsed_ms;
		unsigned long new_vma_pages = 0;

		clock_gettime(CLOCK_MONOTONIC, &fs_start);
		pr_debug("P3[%d] sending new VMA pages (if any)\n", thread_id);

		/* Send pages from new VMAs detected in Phase 3 */
		new_vma_pages = send_new_vma_pages(ctx);

		clock_gettime(CLOCK_MONOTONIC, &fs_end);

		fs_elapsed_ms = (fs_end.tv_sec - fs_start.tv_sec) * 1000 +
				(fs_end.tv_nsec - fs_start.tv_nsec) / 1000000;
		pr_debug("P3[%d] new VMA pages done: %lu pages, TIMING: %ld ms\n",
		       thread_id, new_vma_pages, fs_elapsed_ms);
	}


	clock_gettime(CLOCK_MONOTONIC, &t_end);
	{
		long elapsed_ms = (t_end.tv_sec - t_start.tv_sec) * 1000 +
				  (t_end.tv_nsec - t_start.tv_nsec) / 1000000;

		pr_debug("P3[%d] done: %lu pages, %ld ms\n",
		       thread_id, ctx->pages_sent, elapsed_ms);
	}

p3_sender_exit:
	/* Flush thread-local counters to globals (one atomic per counter) */
	__sync_fetch_and_add(&g_total_sent_pages, tls_total_sent_pages);
	__sync_fetch_and_add(&g_compress_uncompressed_bytes, tls_compress_in_bytes);
	__sync_fetch_and_add(&g_compress_compressed_bytes, tls_compress_out_bytes);
	tls_total_sent_pages = 0;
	tls_compress_in_bytes = 0;
	tls_compress_out_bytes = 0;

	ctx->active = false;
	__sync_fetch_and_sub(&p3_threads_active, 1);
	return NULL;
}

int clone_start_p3_threads(int *sockets, int num_sockets, u64 dst_id, pid_t source_pid)
{
	int i;
	int threads_to_start;

	if (p3_threads_active > 0) {
		pr_warn("P3 threads already running\n");
		return 0;
	}

	/* Reset global flags */
	g_last_scan_flag = false;
	g_scan_complete = false;
	g_scanner_freeze_signal = false;
	g_bulk_transfer_done_count = 0;

	/* Build shared work queue for bulk transfer (work-stealing) */
	build_bulk_work_queue(dst_id);

	/* Initialize sender queues */
	if (clone_init_sender_queues()) {
		pr_err("Failed to initialize sender queues\n");
		return -1;
	}

	/* Calculate number of threads to start (before starting scanner) */
	threads_to_start = num_sockets < clone_cfg.num_p3_threads ? num_sockets : clone_cfg.num_p3_threads;
	g_num_sender_threads = threads_to_start;

	/* Start scanner thread */
	if (clone_start_scanner_thread(source_pid)) {
		pr_err("Failed to start scanner thread\n");
		return -1;
	}

	/* Initialize per-connection TLS credentials before spawning threads */
	if (opts.tls) {
		pr_debug("P3 sender: calling tls_global_init()\n");
		BUG_ON(tls_global_init());
		pr_debug("P3 sender: tls_global_init() OK\n");
	}

	/* Start one sender thread per socket */
	p3_total_pages_sent = 0;

	for (i = 0; i < threads_to_start; i++) {
		p3_threads[i].thread_id = i;
		p3_threads[i].socket = sockets[i];
		p3_threads[i].dst_id = dst_id;
		p3_threads[i].source_pid = source_pid;
		p3_threads[i].pages_sent = 0;
		p3_threads[i].active = true;
		p3_threads[i].error = false;
		p3_threads[i].thread = 0;

		if (opts.tls) {
			pr_debug("P3 sender[%d] starting TLS handshake on fd=%d\n",
			       i, sockets[i]);
			p3_threads[i].tls = tls_conn_new(sockets[i], true);
			if (!p3_threads[i].tls) {
				pr_err("P3 sender[%d] TLS handshake FAILED\n", i);
				BUG();
			}
			pr_debug("P3 sender[%d] TLS handshake OK\n", i);
		} else {
			p3_threads[i].tls = NULL;
		}

		__sync_fetch_and_add(&p3_threads_active, 1);

		if (pthread_create(&p3_threads[i].thread, NULL,
				   p3_bulk_sender_thread, &p3_threads[i])) {
			pr_perror("Failed to create P3 thread %d", i);
			p3_threads[i].active = false;
			__sync_fetch_and_sub(&p3_threads_active, 1);
			/* Continue with remaining threads */
		}
	}

	pr_debug("Started %d P3 bulk sender threads (%d sockets)\n",
		p3_threads_active, threads_to_start);
	return p3_threads_active > 0 ? 0 : -1;
}

void clone_wait_p3_threads(void)
{
	int i;
	unsigned long total = 0;
	int errors = 0;
	struct timespec t_scanner_done, t_senders_done;
	long scanner_ms, senders_ms, total_ms;

	/* Wait for scanner thread first */
	clone_wait_scanner_thread();
	clock_gettime(CLOCK_MONOTONIC, &t_scanner_done);

	/* Then wait for sender threads */
	for (i = 0; i < clone_cfg.num_p3_threads; i++) {
		if (p3_threads[i].thread) {
			pthread_join(p3_threads[i].thread, NULL);
			total += p3_threads[i].pages_sent;
			if (p3_threads[i].error)
				errors++;
			p3_threads[i].thread = 0;
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &t_senders_done);

	/* Tear down TLS sessions and close P3 sockets so target receivers get EOF */
	for (i = 0; i < clone_cfg.num_p3_threads; i++) {
		if (p3_threads[i].tls) {
			tls_conn_free(p3_threads[i].tls);
			p3_threads[i].tls = NULL;
		}
		if (p3_threads[i].socket >= 0) {
			close(p3_threads[i].socket);
			p3_threads[i].socket = -1;
		}
	}

	p3_total_pages_sent = total;
	p3_threads_active = 0;

	/* Print timing breakdown from freeze signal */
	scanner_ms = (t_scanner_done.tv_sec - g_freeze_signal_time.tv_sec) * 1000 +
		     (t_scanner_done.tv_nsec - g_freeze_signal_time.tv_nsec) / 1000000;
	senders_ms = (t_senders_done.tv_sec - t_scanner_done.tv_sec) * 1000 +
		     (t_senders_done.tv_nsec - t_scanner_done.tv_nsec) / 1000000;
	total_ms = (t_senders_done.tv_sec - g_freeze_signal_time.tv_sec) * 1000 +
		   (t_senders_done.tv_nsec - g_freeze_signal_time.tv_nsec) / 1000000;

	pr_debug("P3 TIMING from freeze: scanner=%ld ms, senders=%ld ms, total=%ld ms, %lu pages\n",
	       scanner_ms, senders_ms, total_ms, total);

	/*
	 * Verify all scanned pages were sent. Subtract pages that were
	 * legitimately skipped because their VMA vanished between
	 * enumeration and process_vm_readv (ADD/REMOVE race on a Phase-2
	 * munmap) — the scanner counted those pages in `scanned` but
	 * there was nothing left to read for them.
	 */
	{
		unsigned long scanned = __atomic_load_n(&g_total_scanned_pages, __ATOMIC_ACQUIRE);
		unsigned long sent = __atomic_load_n(&g_total_sent_pages, __ATOMIC_ACQUIRE);
		unsigned long skipped = __atomic_load_n(&g_vma_vanished_skipped_pages,
							__ATOMIC_ACQUIRE);
		unsigned long expected_sent = (skipped > scanned) ? 0 : scanned - skipped;

		pr_debug("P3 verification: scanned=%lu sent=%lu vma_vanished_skipped=%lu expected_sent=%lu\n",
		       scanned, sent, skipped, expected_sent);

		if (sent != expected_sent) {
			/*
			 * If a sender thread hit an error mid-flight we
			 * will legitimately end up with sent < expected.
			 * Surface the mismatch via clone_p3_had_error()
			 * instead of BUG()-ing and aborting, so the main
			 * dump path can clean up rather than core-dump.
			 */
			pr_err("P3 page count mismatch: scanned=%lu sent=%lu skipped=%lu (expected_sent=%lu, diff=%ld)\n",
			       scanned, sent, skipped, expected_sent,
			       (long)expected_sent - (long)sent);
			if (errors == 0) {
				/* No sender reported an error but we're
				 * short anyway — treat as a hard error. */
				errors = 1;
			}
		}
	}

	if (errors > 0) {
		pr_err("P3 threads completed with %d errors — dump is not usable\n",
		       errors);
		clone_p3_mark_had_error();
	}
}

static volatile int g_p3_had_error = 0;

void clone_p3_mark_had_error(void)
{
	__atomic_store_n(&g_p3_had_error, 1, __ATOMIC_RELEASE);
}

bool clone_p3_had_error(void)
{
	return __atomic_load_n(&g_p3_had_error, __ATOMIC_ACQUIRE) != 0;
}

unsigned long clone_p3_pages_sent(void)
{
	return p3_total_pages_sent;
}

int clone_get_num_p3_threads(void)
{
	return clone_cfg.num_p3_threads;
}

/*
 * Check if ready to freeze.
 * With pre-scan enabled: returns true when scanner signals freeze.
 * Without pre-scan: returns true immediately after bulk transfer completes.
 */
bool clone_all_threads_below_threshold(void)
{
	if (clone_cfg.pre_scan) {
		/* Scanner decides when to freeze based on total dirty pages < threshold */
		return g_last_scan_flag && p3_threads_active > 0;
	} else {
		/* No pre-scan: freeze immediately after bulk transfer completes */
		int done = __atomic_load_n(&g_bulk_transfer_done_count, __ATOMIC_ACQUIRE);
		int total = __atomic_load_n(&g_num_sender_threads, __ATOMIC_ACQUIRE);
		return done >= total && p3_threads_active > 0;
	}
}

/*
 * Signal P3 threads to do final scan and exit.
 * Called by main thread after freezing the process.
 */
void clone_signal_last_scan(void)
{
	pr_debug("Convergence: signaling last scan\n");
	clock_gettime(CLOCK_MONOTONIC, &g_freeze_signal_time);
	g_last_scan_flag = true;

	clone_signal_scanner_freeze();  /* Signal scanner to do final scan */
	__sync_synchronize();  /* Memory barrier */
}
