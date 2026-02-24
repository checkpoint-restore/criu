#ifndef __CR_ATOMIC_BITMAP_H__
#define __CR_ATOMIC_BITMAP_H__

#include <stdbool.h>
#include <stdint.h>

/*
 * Inline helpers for per-page bitmaps (1 bit per page).
 *
 * Memory ordering and thread safety:
 *   atomic_bitmap_set/clear    – RMW with RELEASE ordering, safe for concurrent writers
 *   atomic_bitmap_test         – Load with ACQUIRE ordering, safe for concurrent readers
 *   bitmap_test_nonatomic      – Plain read, safe when:
 *                                 (a) Single-threaded reader of single-threaded writer, OR
 *                                 (b) Single-threaded reader with atomic writers (sent_bitmap pattern)
 *                                     where false negatives are acceptable (idempotent sentinel bits)
 *
 * Typical usage:
 *   cow_bitmap:   Thread 1 sets atomically, Thread 3 tests atomically (full sync)
 *   sent_bitmap:  Thread 3 sets non-atomically, Thread 3 tests non-atomically (same thread)
 *
 * All functions take a byte-array bitmap and a zero-based page index.
 */

#define BITMAP_ALLOC_SIZE(nr_pages) (((nr_pages) + 7) / 8)

static inline void atomic_bitmap_set(uint8_t *bitmap, unsigned long page_idx)
{
	__atomic_fetch_or(&bitmap[page_idx / 8],
			  (uint8_t)(1 << (page_idx % 8)),
			  __ATOMIC_RELEASE);
}

static inline bool atomic_bitmap_test(const uint8_t *bitmap,
				      unsigned long page_idx)
{
	uint8_t val = __atomic_load_n(&((uint8_t *)bitmap)[page_idx / 8],
				      __ATOMIC_ACQUIRE);
	return (val & (1 << (page_idx % 8))) != 0;
}

static inline void atomic_bitmap_clear(uint8_t *bitmap, unsigned long page_idx)
{
	__atomic_fetch_and(&bitmap[page_idx / 8],
			   (uint8_t)~(1 << (page_idx % 8)),
			   __ATOMIC_RELEASE);
}

/*
 * Non-atomic test - plain memory load without ordering guarantees.
 * Safe for single-threaded reader contexts where false negatives are acceptable.
 */
static inline bool bitmap_test_nonatomic(const unsigned char *bitmap,
					 unsigned long page_idx)
{
	return (bitmap[page_idx / 8] & (1 << (page_idx % 8))) != 0;
}

/*
 * Non-atomic set - plain memory store without ordering guarantees.
 * Safe for single-threaded contexts only (no concurrent writers).
 */
static inline void bitmap_set_nonatomic(unsigned char *bitmap,
					unsigned long page_idx)
{
	bitmap[page_idx / 8] |= (1 << (page_idx % 8));
}

#endif /* __CR_ATOMIC_BITMAP_H__ */
