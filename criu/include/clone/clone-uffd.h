#ifndef __CR_CLONE_UFFD_H__
#define __CR_CLONE_UFFD_H__

#include <stdbool.h>
#include "int.h"

/* Forward declarations */
struct list_head;
struct epoll_event;

#ifdef CONFIG_HAS_LZ4

/* Initialize CLONE page buffer (hash table, locks) */
int clone_page_buffer_init(void);

/* Initialize page pool for a receiver thread (call once per thread) */
int clone_page_buffer_thread_init(int thread_id);

/* Lookup page in buffer (thread-safe) - returns data pointer or NULL */
void *clone_page_buffer_lookup_and_remove(unsigned long vaddr);

/*
 * Add pages to a 256KB-aligned batch in the buffer.
 * base_vaddr must be 256KB-aligned.
 * Pages live at data + page_offset * PAGE_SIZE.
 * owns_data=true: data is a CLONE_BATCH_PAGES pool allocation, ownership
 *                 transferred. New entry: zero-copy. Existing: memcpy + free.
 * owns_data=false: data is a temp buffer, only read from. New entry:
 *                  allocates pool internally. Existing: memcpy only.
 */
int clone_page_buffer_add_batch(unsigned long base_vaddr, void *data,
			      int nr_pages, int page_offset,
			      int thread_id, bool owns_data);

/*
 * Get data pointer for an existing batch entry.
 * Returns entry->data or NULL. Caller can decompress directly into it.
 *
 * LOCKING: On success (non-NULL return) the entry's hash lock is held
 * on return. The caller MUST call clone_page_buffer_mark_pages() for the
 * same base_vaddr to release it. Do not block between these calls.
 * On NULL return no lock is held.
 */
void *clone_page_buffer_get_data_ptr(unsigned long base_vaddr,
				   int page_offset, int nr_pages);

/*
 * Mark pages valid after direct decompress into entry->data.
 * LOCKING: Must be called after a successful clone_page_buffer_get_data_ptr().
 * Releases the hash lock held by get_data_ptr().
 */
void clone_page_buffer_mark_pages(unsigned long base_vaddr,
				int page_offset, int nr_pages);

/* Get current page count */
unsigned long clone_page_buffer_count(void);


/* Start background drain thread (lpis needed for EAGAIN handling) */
int clone_start_drain_thread(struct list_head *lpis);

/* Check if drain thread is running */
bool clone_drain_thread_running(void);

/* Remove all pages in range from buffer (for UNMAP/REMOVE events) */
void clone_page_buffer_remove_range(unsigned long start, unsigned long len);

/* Re-add page to buffer for EAGAIN retry (takes ownership of data) */
void clone_page_buffer_readd(unsigned long vaddr, void *data);

/*
 * EAGAIN Request Handling (CLONE mode)
 */
struct lazy_pages_info;
extern int clone_queue_eagain_request(struct lazy_pages_info *lpi, __u64 address,
				    unsigned long nr_pages, void *buf, const char *op_name);
extern int clone_queue_drain_eagain_request(struct list_head *lpis, unsigned long vaddr, void *data);
extern bool clone_is_eagain_queue_empty(void);
extern int clone_process_eagain_requests(void);

/* Find IOV for address (wrapper for uffd.c find_iov) */
struct lazy_iov;
extern struct lazy_iov *clone_find_iov(struct lazy_pages_info *lpi, unsigned long addr);

/*
 * CLONE Restore State Management
 */

/* Check/set if restore has connected (uffd available) */
extern bool clone_is_restore_connected(void);
extern void clone_set_restore_connected(bool connected);


/* Check/set if all pages have been sent by the source */
extern bool clone_is_all_pages_sent_received(void);
extern void clone_set_all_pages_sent_received(void);

/* Return uffd for a given vaddr (for background drain thread) */
extern int clone_get_uffd_for_vaddr(struct list_head *lpis, unsigned long vaddr);

/*
 * CLONE Phase 2/3 Infrastructure
 * These functions handle the pre-buffering and convergence phases.
 */

/* Initialize control message reader for CLONE mode */
extern int clone_setup_prebuffer_reader(void);


/*
 * CLONE_TRACK_* flags for clone_uffd_copy()
 */
#define CLONE_TRACK_STRICT    (1 << 0)  /* BUG() on EEXIST/ERROR (drain mode) */
#define CLONE_TRACK_RETRY     (1 << 1)  /* Retry mode: no buffer stats, return -EAGAIN */

/*
 * Unified UFFDIO_COPY with full tracking for CLONE mode.
 * Handles buffer stats, page state, unmapped tracker, and EAGAIN queue.
 *
 * Returns:
 *   1 - success (page copied)
 *   0 - soft handled (ENOENT unmapped, EAGAIN queued, EEXIST already done)
 *  -1 - error
 *  -EAGAIN - kernel busy (only with CLONE_TRACK_RETRY flag)
 */
extern int clone_uffd_copy(int uffd, unsigned long vaddr, void *data,
			 unsigned long nr_pages, struct lazy_pages_info *lpi,
			 struct list_head *lpis, unsigned int flags,
			 const char *caller);

/*
 * Queue EAGAIN for zero operation (simpler than full clone_uffd_copy path).
 * Called directly from uffd_zero() for EAGAIN handling.
 */


/*
 * CLONE bulk IO complete callback
 * This is the io_complete callback for CLONE mode page reads.
 */
extern int clone_uffd_io_complete_bulk(struct lazy_pages_info *lpi,
				     unsigned long vaddr, unsigned long nr_pages);

/*
 * Handle UNMAP/REMOVE event in CLONE mode.
 * Marks pages as unmapped in trackers and removes from buffer.
 */
extern void clone_handle_remove_event(unsigned long start, unsigned long len);

/*
 * Handle page fault in CLONE mode.
 * Serves page from buffer or zeros if not found.
 * Returns: 0 on success, -1 on error
 */
extern int clone_handle_page_fault(struct lazy_pages_info *lpi, unsigned long address);

/*
 * Signal lazy-pages that tasks are frozen, wait for drain complete.
 * Called from lazy_pages_finish_restore() after catch_tasks().
 * Returns: 0 on success, -1 on error
 */
extern int clone_wait_for_drain(int fd);

/*
 * CLONE post-connect initialization in handle_lazy_accept.
 */
extern int clone_handle_lazy_accept_post_connect(struct list_head *lpis);

#else /* !CONFIG_HAS_LZ4 */

/* Stubs when LZ4/CLONE support is not compiled in */
static inline int clone_page_buffer_init(void) { return -1; }
static inline int clone_page_buffer_thread_init(int id) { (void)id; return -1; }
static inline void *clone_page_buffer_lookup_and_remove(unsigned long v) { (void)v; return NULL; }
static inline int clone_page_buffer_add_batch(unsigned long base, void *data, int nr, int off, int tid, bool owns)
{
	(void)base; (void)data; (void)nr; (void)off; (void)tid; (void)owns;
	return -1;
}
static inline void *clone_page_buffer_get_data_ptr(unsigned long b, int o, int n)
{
	(void)b; (void)o; (void)n;
	return NULL;
}
static inline void clone_page_buffer_mark_pages(unsigned long b, int o, int n) { (void)b; (void)o; (void)n; }
static inline unsigned long clone_page_buffer_count(void) { return 0; }
static inline int clone_start_drain_thread(struct list_head *lpis) { (void)lpis; return -1; }
static inline bool clone_drain_thread_running(void) { return false; }
static inline void clone_page_buffer_remove_range(unsigned long s, unsigned long l) { (void)s; (void)l; }
static inline void clone_page_buffer_readd(unsigned long v, void *d) { (void)v; (void)d; }
static inline bool clone_is_eagain_queue_empty(void) { return true; }
static inline int clone_process_eagain_requests(void) { return 0; }
static inline bool clone_is_restore_connected(void) { return false; }
static inline void clone_set_restore_connected(bool c) { (void)c; }
static inline bool clone_is_all_pages_sent_received(void) { return false; }
static inline void clone_set_all_pages_sent_received(void) { }
static inline int clone_get_uffd_for_vaddr(struct list_head *lpis, unsigned long v)
{
	(void)lpis; (void)v;
	return -1;
}
static inline int clone_setup_prebuffer_reader(void) { return -1; }
static inline void clone_handle_remove_event(unsigned long s, unsigned long l) { (void)s; (void)l; }
static inline int clone_handle_page_fault(void *lpi, unsigned long addr)
{
	(void)lpi; (void)addr;
	return -1;
}
static inline int clone_wait_for_drain(int fd) { (void)fd; return -1; }
static inline int clone_handle_lazy_accept_post_connect(struct list_head *lpis) { (void)lpis; return -1; }

#endif /* CONFIG_HAS_LZ4 */

#endif /* __CR_CLONE_UFFD_H__ */
