#ifndef __CR_UNMAPPED_TRACKER_H__
#define __CR_UNMAPPED_TRACKER_H__

#include <stdbool.h>

/*
 * Production-safe tracker for unmapped pages.
 * Used to verify that DISCARDED state transitions are expected
 * (page was unmapped) vs unexpected (a bug).
 *
 * Thread-safe with fine-grained locking.
 */

#ifdef CONFIG_HAS_LZ4

int unmapped_tracker_init(void);
void unmapped_tracker_destroy(void);

/* Mark a range as unmapped (called from handle_remove) */
void unmapped_tracker_mark_range(unsigned long start, unsigned long len);

/* Check if a page was unmapped (returns true if unmapped) */
bool unmapped_tracker_is_unmapped(unsigned long vaddr);

/* Remove tracking for a page (optional cleanup after handling) */
void unmapped_tracker_clear(unsigned long vaddr);

#else /* !CONFIG_HAS_LZ4 */

static inline int unmapped_tracker_init(void) { return 0; }
static inline void unmapped_tracker_destroy(void) { }
static inline void unmapped_tracker_mark_range(unsigned long s, unsigned long l) { (void)s; (void)l; }
static inline bool unmapped_tracker_is_unmapped(unsigned long v) { (void)v; return false; }
static inline void unmapped_tracker_clear(unsigned long v) { (void)v; }

#endif /* CONFIG_HAS_LZ4 */

#endif /* __CR_UNMAPPED_TRACKER_H__ */
