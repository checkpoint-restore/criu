#ifndef __CR_CLONE_DUMP_H_
#define __CR_CLONE_DUMP_H_

#include "types.h"

struct pstree_item;
struct vm_area_list;
struct parasite_ctl;

/* Forward declaration */
struct page_pipe_buf;

#ifdef CONFIG_HAS_LZ4

/* Queue entry for CLONE pages waiting to be sent */
struct clone_page_queue_entry {
	unsigned long vaddr;
	void *data;                      /* Original page content (4KB) */
	struct page_pipe_buf *ppb;      /* Buffer containing this page */
	unsigned int seg_idx;            /* Segment index within buffer */
	unsigned long page_idx_in_seg;   /* Page index within segment */
	struct clone_page_queue_entry *next;   /* Used by consumer-side putback list */
};

/* CLONE dump phases for phased migration */
enum clone_dump_phase {
	CLONE_PHASE_IDLE = 0,
	CLONE_PHASE_ASYNC_BULK,      /* WP_ASYNC active, bulk transfer in progress */
	CLONE_PHASE_SCAN,            /* Process frozen, scanning dirty pages */
	CLONE_PHASE_DONE,
};

/**
 * clone_dump_fini - Clean up CLONE dump resources
 *
 * Releases all resources allocated for CLONE tracking.
 */
extern void clone_dump_fini(void);

/**
 * clone_set_dst_id - Update the dst_id for page transfer
 * @dst_id: Process identifier (vpid)
 *
 * In CLONE phased dump, the initial dst_id is set before collect_pstree_ids()
 * populates vpid. Call this after collect_pstree_ids() to fix it.
 */
extern void clone_set_dst_id(u64 dst_id);

/**
 * clone_dump_is_vma_tracked - Check whether a VMA is CLONE-tracked
 * @source_pid: Source process pid from dump-time tree
 * @start: VMA start address
 * @end: VMA end address
 *
 * Returns: true if this exact VMA was successfully registered for CLONE.
 */
extern bool clone_dump_is_vma_tracked(pid_t source_pid,
				    unsigned long start,
				    unsigned long end);

struct clone_page_queue_entry;


/**
 * clone_dump_init_async - Initialize CLONE dump with WP_ASYNC mode
 * @item: Process tree item to set up CLONE tracking for
 * @vma_area_list: List of VMAs to track
 * @ctl: Parasite control structure (unused, kept for API consistency)
 *
 * Sets up userfaultfd with WP_ASYNC for non-blocking write tracking.
 * Does NOT start the monitor thread since WP_ASYNC doesn't generate faults.
 * Dirty pages are later discovered via PAGEMAP_SCAN.
 *
 * Returns: 0 on success, -1 on error
 */
extern int clone_dump_init_async(struct pstree_item *item,
			       struct vm_area_list *vma_area_list,
			       struct parasite_ctl *ctl);


/**
 * clone_get_phase - Get the current CLONE dump phase
 *
 * Returns: Current clone_dump_phase value
 */
extern enum clone_dump_phase clone_get_phase(void);

/**
 * clone_set_phase - Set the current CLONE dump phase
 * @phase: New phase to set
 */
extern void clone_set_phase(enum clone_dump_phase phase);

/**
 * clone_is_phased_skeleton_dump - Check if we're in Phase 3 skeleton dump mode
 *
 * In CLONE phased migration, Phase 3 dumps everything EXCEPT memory pages
 * (which were already transferred in Phase 2). This function returns true
 * when dump_one_task() should skip page dumping and related CLONE init.
 *
 * Returns: true if in skeleton dump mode, false otherwise
 */
extern bool clone_is_phased_skeleton_dump(void);

/**
 * clone_detect_new_vmas - Detect VMAs that appeared after Phase 1
 * @vmas: Current VMA list (from collect_mappings in Phase 3)
 * @new_ranges: Output array of [start, len, ...] pairs
 * @nr_new_ranges: Output count of new ranges
 *
 * Compares current VMAs with Phase 1 tracked VMAs to find new or
 * extended regions. These need to be marked dirty for WP_SYNC.
 * Caller must xfree() the new_ranges array.
 *
 * Returns: 0 on success, -1 on error
 */
extern int clone_detect_new_vmas(struct vm_area_list *vmas,
			       unsigned long **new_ranges,
			       unsigned int *nr_new_ranges);

/**
 * clone_cleanup_async_uffd - Close async uffd without unregistering VMAs
 *
 * Closes the async uffd file descriptor directly without issuing
 * UFFDIO_UNREGISTER for each VMA. The kernel automatically cleans up
 * registrations when the fd is closed. This avoids expensive page table
 * walks that can take minutes on large memory systems (300GB+).
 */
extern void clone_cleanup_async_uffd(void);

/**
 * clone_record_unmapped_range - Record a range that was unmapped during Phase 2
 * @start: Start address of unmapped range
 * @len: Length of unmapped range
 *
 * Called from UFFD event reader thread when UFFD_EVENT_UNMAP/REMOVE is
 * received, or from bulk sender when process_vm_readv returns EFAULT.
 * Phase 3 checks if new VMAs appeared at these addresses to detect remaps.
 *
 * Thread-safe: multiple callers may run in parallel.
 */
extern void clone_record_unmapped_range(unsigned long start, unsigned long len);

/**
 * cr_dump_clone_finish - Clone-specific finish operations
 * @ret: current return status (0 = success so far)
 *
 * Handles signaling the target, optional comparison, unfreezing the
 * process, and cleanup. Called from cr_dump_finish() when clone dump is
 * complete.
 *
 * Returns: updated return status
 */
extern int cr_dump_clone_finish(int ret);

/**
 * cr_dump_tasks_clone_phased - CLONE phased migration orchestration
 * @pid: Target process ID
 *
 * Implements the WP_ASYNC → WP_SYNC phased migration flow:
 *   Phase 1: pre_dump → WP_ASYNC all VMAs → resume immediately
 *   Phase 2: bulk page transfer (process running, writes tracked async)
 *   Phase 3: freeze → dump skeleton (no pages) → PAGEMAP_SCAN dirty pages
 *   Phase 4: WP_SYNC on dirty pages → resume → convergence
 *
 * Returns: 0 on success, -1 on failure
 */
extern int cr_dump_tasks_clone_phased(pid_t pid);

#else /* !CONFIG_HAS_LZ4 */

/* Stubs when LZ4/CLONE support is not compiled in */
enum clone_dump_phase {
	CLONE_PHASE_IDLE = 0,
	CLONE_PHASE_ASYNC_BULK,
	CLONE_PHASE_SCAN,
	CLONE_PHASE_DONE,
};

static inline void clone_dump_fini(void) { }
static inline void clone_set_dst_id(u64 dst_id) { (void)dst_id; }
static inline bool clone_dump_is_vma_tracked(pid_t pid, unsigned long start, unsigned long end)
{
	(void)pid; (void)start; (void)end;
	return false;
}
static inline int clone_dump_init_async(struct pstree_item *item,
					struct vm_area_list *vmas,
					struct parasite_ctl *ctl)
{
	(void)item; (void)vmas; (void)ctl;
	return -1;
}
static inline enum clone_dump_phase clone_get_phase(void) { return CLONE_PHASE_IDLE; }
static inline void clone_set_phase(enum clone_dump_phase phase) { (void)phase; }
static inline bool clone_is_phased_skeleton_dump(void) { return false; }
static inline int clone_detect_new_vmas(struct vm_area_list *vmas,
					unsigned long **new_ranges,
					unsigned int *nr_new_ranges)
{
	(void)vmas; (void)new_ranges; (void)nr_new_ranges;
	return -1;
}
static inline void clone_cleanup_async_uffd(void) { }
static inline void clone_record_unmapped_range(unsigned long start, unsigned long len)
{
	(void)start; (void)len;
}
static inline int cr_dump_clone_finish(int ret) { return ret; }
static inline int cr_dump_tasks_clone_phased(pid_t pid) { (void)pid; return -1; }

#endif /* CONFIG_HAS_LZ4 */

#endif /* __CR_CLONE_DUMP_H_ */
