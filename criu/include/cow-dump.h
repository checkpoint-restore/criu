#ifndef __CR_COW_DUMP_H_
#define __CR_COW_DUMP_H_

#include "types.h"
#include "common/list.h"

struct pstree_item;
struct vm_area_list;
struct parasite_ctl;

#define COW_HASH_BITS 10
#define COW_HASH_SIZE (1 << COW_HASH_BITS)

struct cow_page {
	unsigned long vaddr;
	void *data;
	struct hlist_node hash;
};


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

/**
 * cow_start_monitor_thread - Start background thread to monitor page faults
 *
 * Creates a pthread that continuously monitors the userfaultfd for
 * write faults and handles them immediately, preventing the target
 * process from blocking during the dump phase.
 *
 * Returns: 0 on success, -1 on error
 */
extern int cow_start_monitor_thread(void);

/**
 * cow_stop_monitor_thread - Stop the monitoring thread
 *
 * Signals the monitor thread to stop and waits for it to complete.
 *
 * Returns: 0 on success, -1 on error
 */
extern int cow_stop_monitor_thread(void);

/**
 * cow_get_uffd - Get the userfaultfd file descriptor
 *
 * Returns the userfaultfd associated with the current COW dump session.
 *
 * Returns: userfaultfd on success, -1 if COW dump not initialized
 */
extern int cow_get_uffd(void);

/**
 * cow_lookup_and_remove_page - Look up and remove a COW page
 * @vaddr: Virtual address of the page
 *
 * Thread-safe lookup and removal of a copied page from the hash table.
 * The caller is responsible for freeing the returned cow_page structure
 * and its data.
 *
 * Returns: cow_page structure on success, NULL if not found
 */
extern struct cow_page *cow_lookup_and_remove_page(unsigned long vaddr);

#endif /* __CR_COW_DUMP_H_ */
