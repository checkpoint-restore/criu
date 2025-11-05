#ifndef __CR_COW_DUMP_H_
#define __CR_COW_DUMP_H_

#include "types.h"

struct pstree_item;
struct vm_area_list;
struct parasite_ctl;

/* COW dump mode - write-tracking based live migration */

/**
 * cr_cow_mem_dump - Main entry point for COW-based memory dump
 * 
 * This function implements copy-on-write based live migration where
 * the source process continues running while dirty pages are tracked
 * and transferred iteratively.
 *
 * Returns: 0 on success, -1 on error
 */
extern int cr_cow_mem_dump(void);

/**
 * cow_dump_init - Initialize COW dump for a process
 * @item: Process tree item to set up COW tracking for
 * @vma_area_list: List of VMAs to track
 * @ctl: Parasite control structure for RPC
 *
 * Sets up userfaultfd with write-protection for all writable memory
 * regions of the target process. The registration is performed via
 * parasite RPC to ensure it runs in the target process's context.
 *
 * Returns: 0 on success, -1 on error
 */
extern int cow_dump_init(struct pstree_item *item, struct vm_area_list *vma_area_list, struct parasite_ctl *ctl);

/**
 * cow_dump_fini - Clean up COW dump resources
 *
 * Releases all resources allocated for COW tracking.
 */
extern void cow_dump_fini(void);

/**
 * cow_check_kernel_support - Check if kernel supports COW dump
 *
 * Verifies that the kernel has necessary userfaultfd write-protect
 * features (requires Linux 5.7+).
 *
 * Returns: true if supported, false otherwise
 */
extern bool cow_check_kernel_support(void);

#endif /* __CR_COW_DUMP_H_ */
