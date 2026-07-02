#ifndef __CR_PAGE_STATE_TRACKER_H__
#define __CR_PAGE_STATE_TRACKER_H__

#include <stdbool.h>
#include "int.h"
#include "clone/clone-conf.h"  /* CONFIG_PAGE_STATE_TRACKER */

/*
 * Comprehensive page state tracking for CLONE lazy restore debugging.
 * Tracks all state transitions and validates them to detect bugs.
 */
enum page_state {
	PAGE_STATE_UNKNOWN = 0,       /* Not yet tracked */
	PAGE_STATE_IN_BUFFER,         /* In CLONE buffer (after clone_page_buffer_add_batch) */
	PAGE_STATE_PF_PENDING,        /* PF handler found in buffer, about to copy */
	PAGE_STATE_DRAIN_PENDING,     /* Drain thread removed from buffer, about to copy */
	PAGE_STATE_URGENT_PENDING,    /* Urgent request received, about to copy */
	PAGE_STATE_EAGAIN_QUEUED,     /* UFFDIO_COPY got EAGAIN, queued for retry */
	PAGE_STATE_COPIED,            /* UFFDIO_COPY succeeded */
	PAGE_STATE_DIRTY,             /* Discarded due to dirty bitmap, will be re-sent */
	PAGE_STATE_DISCARDED,         /* Discarded due to error (EEXIST, ENOENT, etc.) */
	PAGE_STATE_UNMAPPED,          /* Region was unmapped, page no longer valid */
};

#ifdef CONFIG_PAGE_STATE_TRACKER

extern int page_state_init(void);
extern void page_state_destroy(void);
extern int page_state_set(unsigned long vaddr, enum page_state new_state);
extern enum page_state page_state_get(unsigned long vaddr);
extern void page_state_print_stats(void);
extern const char *page_state_name(enum page_state state);

/* Print full history of state changes for a page - call on error for debugging */
extern void page_state_print_history(unsigned long vaddr);

/* Mark all pages in a range as unmapped (for REMOVE/UNMAP events) */
extern void page_state_mark_range_unmapped(unsigned long start, unsigned long len);

/* Mark COPIED/DISCARDED pages in dirty ranges as DIRTY for re-receive */
extern void page_state_mark_dirty_ranges(unsigned long *ranges, unsigned int nr_ranges);

/* Verify all pages reached terminal states (COPIED, DISCARDED, UNMAPPED) - BUGs if not */
extern int page_state_verify_all_terminal(void);

/* CRC tracking for debugging dirty page races */
/* Set state with CRC - call when adding to buffer */
extern int page_state_set_with_crc(unsigned long vaddr, enum page_state new_state,
				   const void *data);

/* Check CRC before copy - returns true if match or no previous CRC */
extern bool page_state_check_crc(unsigned long vaddr, const void *data, u32 *stored_crc);

/* Get buffer count (how many times page was buffered) */
extern u32 page_state_get_buffer_count(unsigned long vaddr);

/* Get stored CRC for a page */
extern u32 page_state_get_crc(unsigned long vaddr);

/*
 * True if the page's history ever went through PF_PENDING or
 * URGENT_PENDING. These pages were served to the target process via
 * UFFDIO_COPY and are owned by it afterwards — they may legitimately
 * differ from the source snapshot when compare runs.
 */
extern bool page_state_was_pf_served(unsigned long vaddr);

#else /* !CONFIG_PAGE_STATE_TRACKER */

static inline int page_state_init(void) { return 0; }
static inline void page_state_destroy(void) { }
static inline int page_state_set(unsigned long vaddr, enum page_state new_state)
{
	(void)vaddr;
	(void)new_state;
	return 0;
}
static inline enum page_state page_state_get(unsigned long vaddr)
{
	(void)vaddr;
	return PAGE_STATE_UNKNOWN;
}
static inline void page_state_print_stats(void) { }
static inline const char *page_state_name(enum page_state state)
{
	(void)state;
	return "DISABLED";
}
static inline void page_state_print_history(unsigned long vaddr)
{
	(void)vaddr;
}
static inline void page_state_mark_range_unmapped(unsigned long start, unsigned long len)
{
	(void)start;
	(void)len;
}
static inline void page_state_mark_dirty_ranges(unsigned long *ranges, unsigned int nr_ranges)
{
	(void)ranges;
	(void)nr_ranges;
}
static inline int page_state_verify_all_terminal(void) { return 0; }
static inline int page_state_set_with_crc(unsigned long vaddr, enum page_state new_state,
					  const void *data)
{
	(void)vaddr;
	(void)new_state;
	(void)data;
	return 0;
}
static inline bool page_state_check_crc(unsigned long vaddr, const void *data, u32 *stored_crc)
{
	(void)vaddr;
	(void)data;
	(void)stored_crc;
	return true;
}
static inline u32 page_state_get_buffer_count(unsigned long vaddr)
{
	(void)vaddr;
	return 0;
}
static inline u32 page_state_get_crc(unsigned long vaddr)
{
	(void)vaddr;
	return 0;
}
static inline bool page_state_was_pf_served(unsigned long vaddr)
{
	(void)vaddr;
	return false;
}

#endif /* CONFIG_PAGE_STATE_TRACKER */

#endif /* __CR_PAGE_STATE_TRACKER_H__ */
