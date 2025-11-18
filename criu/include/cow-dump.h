#ifndef __CR_COW_DUMP_H_
#define __CR_COW_DUMP_H_

#include "types.h"
#include "common/list.h"

struct pstree_item;
struct vm_area_list;
struct parasite_ctl;

#define COW_HASH_BITS 16
#define COW_HASH_SIZE (1 << COW_HASH_BITS)

struct cow_page {
	unsigned long vaddr;
	void *data;
	struct hlist_node hash;
};

/* Queue entry for COW pages waiting to be sent */
struct cow_page_queue_entry {
	unsigned long vaddr;
	struct list_head list;
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
 * cow_lookup_page - Look up a COW page without removing it
 * @vaddr: Virtual address of the page
 *
 * Look up a page in the COW hash table without removing it.
 * IMPORTANT: Caller must hold the hash bucket lock for this page.
 *
 * Returns: cow_page structure on success, NULL if not found
 */
extern struct cow_page *cow_lookup_page(unsigned long vaddr);

/**
 * cow_remove_page - Remove and free a COW page
 * @vaddr: Virtual address of the page
 *
 * Remove a page from the COW hash table and free its memory.
 * IMPORTANT: Caller must hold the hash bucket lock for this page.
 */
extern void cow_remove_page(unsigned long vaddr);

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

/**
 * cow_get_hash_lock - Get pointer to the spinlock for a page's hash bucket
 * @vaddr: Virtual address of the page
 *
 * Returns the spinlock that protects the hash bucket for the given address.
 * Used for manual locking around cow_lookup_page/cow_remove_page.
 *
 * Returns: Pointer to the spinlock
 */
extern pthread_spinlock_t *cow_get_hash_lock(unsigned long vaddr);

struct cow_page_queue_entry;

/**
 * cow_get_next_page - Get next COW page from the queue
 *
 * Thread-safe dequeue of the next COW page that needs to be sent.
 * The caller is responsible for freeing the returned entry.
 *
 * Returns: cow_page_queue_entry on success, NULL if queue is empty
 */
extern struct cow_page_queue_entry *cow_get_next_page(void);

/**
 * cow_has_pending_pages - Check if there are pending COW pages
 *
 * Thread-safe check for whether the COW page queue has any entries.
 *
 * Returns: true if there are pending pages, false otherwise
 */
extern bool cow_has_pending_pages(void);

#endif /* __CR_COW_DUMP_H_ */
