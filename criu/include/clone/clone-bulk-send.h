#ifndef __CR_CLONE_BULK_SEND_H__
#define __CR_CLONE_BULK_SEND_H__

#include "int.h"
#include "clone/clone-conf.h"
#include <pthread.h>

#ifdef CONFIG_HAS_LZ4

#include "clone/spsc-queue.h"

struct tls_conn;

/*
 * Dirty region entry - passed from scanner thread to sender threads via SPSC queue.
 * Each entry represents a contiguous range of dirty pages to be transferred.
 */
struct dirty_region_entry {
	unsigned long start;      /* Start address of dirty region */
	unsigned long end;        /* End address of dirty region */
	u64 dst_id;               /* Destination image ID */
	pid_t source_pid;         /* Source process PID */
};

/* SPSC queue node for dirty regions */
DECLARE_SPSC_NODE(dirty_region, struct dirty_region_entry);

/*
 * Send a batch of pages with LZ4 compression.
 * Used by bulk sender and dirty page dump.
 *
 * acceleration: LZ4_compress_fast acceleration parameter.
 *   1  - best ratio (equivalent to LZ4_compress_default). All current callers
 *        pass 1: higher values were measured to regress total P3 wall-clock by
 *        shifting the bottleneck into tcp_sendmsg (see send_dirty_slices()).
 *   Larger values trade compression ratio for less CPU.
 */
int send_pages_batch_compressed(struct tls_conn *tls, int sk,
				const void *data, int nr_pages, u64 dst_id,
				unsigned long base_vaddr,
				int acceleration);


/*
 * Initialize sender queues (one per thread).
 * Returns 0 on success, -1 on error.
 */
int clone_init_sender_queues(void);

/*
 * Start the dirty scanner thread.
 * Scanner scans all VMAs and distributes dirty regions to sender queues.
 * Returns 0 on success, -1 on error.
 */
int clone_start_scanner_thread(pid_t source_pid);

/*
 * Signal scanner to do final scan and exit.
 */
void clone_signal_scanner_freeze(void);

/*
 * Wait for scanner thread to complete.
 */
void clone_wait_scanner_thread(void);

/*
 * Check if scanner has completed (for senders to know when to exit).
 */
bool clone_is_scan_complete(void);

/*
 * Start multiple P3 bulk sender threads (up to 20 threads for parallel transfer).
 * Each thread handles 1/N of each VMA's address range and has its own socket.
 * sockets: array of socket file descriptors (one per thread)
 * num_sockets: number of sockets/threads to start (capped at 20)
 * Returns 0 on success, -1 on error.
 */
int clone_start_p3_threads(int *sockets, int num_sockets, u64 dst_id, pid_t source_pid);

/*
 * Wait for all P3 bulk sender threads to complete.
 */
void clone_wait_p3_threads(void);

/*
 * Return true if any P3 sender thread reported a fatal error during
 * bulk transfer, or if the scanned/sent page counts didn't match.
 * The main dump path should check this after clone_wait_p3_threads()
 * and fail the dump cleanly rather than letting the (incomplete)
 * dump be used for restore.
 */
bool clone_p3_had_error(void);

/*
 * Internal helper used by clone_wait_p3_threads() to record the
 * error state. Not intended for callers outside the CLONE subsystem.
 */
void clone_p3_mark_had_error(void);

/*
 * Get total number of pages sent by all P3 threads.
 */
unsigned long clone_p3_pages_sent(void);

/*
 * Get the number of P3 threads (for creating sockets).
 */
int clone_get_num_p3_threads(void);

/*
 * Check if all P3 threads are below dirty page convergence threshold.
 * Returns true only when ALL active threads report < CLONE_DIRTY_CONVERGENCE_THRESHOLD.
 */
bool clone_all_threads_below_threshold(void);

/*
 * Signal P3 threads to do final scan and exit.
 * Called by main thread after freezing the process.
 */
void clone_signal_last_scan(void);

/*
 * Set new VMA ranges detected in Phase 3 for P3 threads to send.
 * ranges: array of [start, len, start, len, ...] pairs
 * nr_ranges: number of ranges
 */
void clone_set_new_vma_ranges(unsigned long *ranges, unsigned int nr_ranges);

/*
 * Free new VMA ranges after P3 threads complete.
 */
void clone_free_new_vma_ranges(void);

#else /* !CONFIG_HAS_LZ4 */

/* Stubs when LZ4/CLONE support is not compiled in */
static inline int clone_init_sender_queues(void) { return -1; }
static inline int clone_start_scanner_thread(pid_t pid) { (void)pid; return -1; }
static inline void clone_signal_scanner_freeze(void) { }
static inline void clone_wait_scanner_thread(void) { }
static inline bool clone_is_scan_complete(void) { return true; }
static inline int clone_start_p3_threads(int *sockets, int num, u64 dst_id, pid_t pid)
{
	(void)sockets; (void)num; (void)dst_id; (void)pid;
	return -1;
}
static inline void clone_wait_p3_threads(void) { }
static inline bool clone_p3_had_error(void) { return true; }
static inline void clone_p3_mark_had_error(void) { }
static inline unsigned long clone_p3_pages_sent(void) { return 0; }
static inline int clone_get_num_p3_threads(void) { return 0; }
static inline bool clone_all_threads_below_threshold(void) { return true; }
static inline void clone_signal_last_scan(void) { }
static inline void clone_set_new_vma_ranges(unsigned long *r, unsigned int n) { (void)r; (void)n; }
static inline void clone_free_new_vma_ranges(void) { }

#endif /* CONFIG_HAS_LZ4 */

#endif /* __CR_CLONE_BULK_SEND_H__ */
