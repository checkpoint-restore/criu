#ifndef __CR_CLONE_BATCH_BITMAP_H__
#define __CR_CLONE_BATCH_BITMAP_H__

#include <stdint.h>

/*
 * CLONE Batch Bitmap - 256-bit bitmap for tracking pages within a batch.
 *
 * Used by batch_buffer_entry to track which pages in a batch are valid.
 * Supports up to 256 pages per batch (1MB with 4KB pages).
 *
 * All operations are static inline for performance since they're called
 * in hot paths (drain threads, page fault handling).
 */

#define CLONE_BITMAP_WORDS 4
#define CLONE_BITMAP_BITS  (CLONE_BITMAP_WORDS * 64)

typedef struct {
	uint64_t words[CLONE_BITMAP_WORDS];
} clone_batch_bitmap_t;

static inline void clone_batch_bitmap_zero(clone_batch_bitmap_t *bm)
{
	bm->words[0] = 0;
	bm->words[1] = 0;
	bm->words[2] = 0;
	bm->words[3] = 0;
}

static inline void clone_batch_bitmap_fill(clone_batch_bitmap_t *bm)
{
	bm->words[0] = ~0ULL;
	bm->words[1] = ~0ULL;
	bm->words[2] = ~0ULL;
	bm->words[3] = ~0ULL;
}

static inline void clone_batch_bitmap_set(clone_batch_bitmap_t *bm, int idx)
{
	int word = idx >> 6;
	int bit = idx & 63;

	bm->words[word] |= (1ULL << bit);
}

static inline void clone_batch_bitmap_clear(clone_batch_bitmap_t *bm, int idx)
{
	int word = idx >> 6;
	int bit = idx & 63;

	bm->words[word] &= ~(1ULL << bit);
}

static inline int clone_batch_bitmap_test(const clone_batch_bitmap_t *bm, int idx)
{
	int word = idx >> 6;
	int bit = idx & 63;

	return (bm->words[word] >> bit) & 1;
}

static inline int clone_batch_bitmap_is_full(const clone_batch_bitmap_t *bm)
{
	return bm->words[0] == ~0ULL &&
	       bm->words[1] == ~0ULL &&
	       bm->words[2] == ~0ULL &&
	       bm->words[3] == ~0ULL;
}

static inline int clone_batch_bitmap_is_empty(const clone_batch_bitmap_t *bm)
{
	return (bm->words[0] | bm->words[1] | bm->words[2] | bm->words[3]) == 0;
}

static inline int clone_batch_bitmap_popcount(const clone_batch_bitmap_t *bm)
{
	return __builtin_popcountll(bm->words[0]) +
	       __builtin_popcountll(bm->words[1]) +
	       __builtin_popcountll(bm->words[2]) +
	       __builtin_popcountll(bm->words[3]);
}

static inline void clone_batch_bitmap_and(clone_batch_bitmap_t *dst,
					const clone_batch_bitmap_t *a,
					const clone_batch_bitmap_t *b)
{
	dst->words[0] = a->words[0] & b->words[0];
	dst->words[1] = a->words[1] & b->words[1];
	dst->words[2] = a->words[2] & b->words[2];
	dst->words[3] = a->words[3] & b->words[3];
}

static inline void clone_batch_bitmap_or(clone_batch_bitmap_t *dst,
				       const clone_batch_bitmap_t *a,
				       const clone_batch_bitmap_t *b)
{
	dst->words[0] = a->words[0] | b->words[0];
	dst->words[1] = a->words[1] | b->words[1];
	dst->words[2] = a->words[2] | b->words[2];
	dst->words[3] = a->words[3] | b->words[3];
}

static inline void clone_batch_bitmap_not(clone_batch_bitmap_t *dst,
					const clone_batch_bitmap_t *src)
{
	dst->words[0] = ~src->words[0];
	dst->words[1] = ~src->words[1];
	dst->words[2] = ~src->words[2];
	dst->words[3] = ~src->words[3];
}

/*
 * Mask bitmap to only include bits [0, limit).
 * Use after NOT operations when batch size < 256 pages.
 */
static inline void clone_batch_bitmap_mask(clone_batch_bitmap_t *bm, int limit)
{
	int full_words = limit >> 6;
	int remaining_bits = limit & 63;
	int i;

	if (remaining_bits > 0) {
		uint64_t mask = (1ULL << remaining_bits) - 1;
		bm->words[full_words] &= mask;
		full_words++;
	}

	for (i = full_words; i < CLONE_BITMAP_WORDS; i++)
		bm->words[i] = 0;
}

static inline void clone_batch_bitmap_copy(clone_batch_bitmap_t *dst,
					 const clone_batch_bitmap_t *src)
{
	dst->words[0] = src->words[0];
	dst->words[1] = src->words[1];
	dst->words[2] = src->words[2];
	dst->words[3] = src->words[3];
}

/*
 * Find next set bit starting from 'start' (inclusive).
 * Returns bit index, or -1 if no more bits are set.
 */
static inline int clone_batch_bitmap_next_set(const clone_batch_bitmap_t *bm, int start)
{
	int word = start >> 6;
	int bit = start & 63;
	uint64_t masked;

	if (start >= CLONE_BITMAP_BITS)
		return -1;

	masked = bm->words[word] & (~0ULL << bit);
	if (masked)
		return (word << 6) + __builtin_ctzll(masked);

	for (word++; word < CLONE_BITMAP_WORDS; word++) {
		if (bm->words[word])
			return (word << 6) + __builtin_ctzll(bm->words[word]);
	}

	return -1;
}

/*
 * Set a range of bits [start, start+count).
 * Handles ranges that span multiple words.
 */
static inline void clone_batch_bitmap_set_range(clone_batch_bitmap_t *bm, int start, int count)
{
	int end = start + count;
	int word, first_bit, last_bit;
	uint64_t mask;

	if (count <= 0 || start >= CLONE_BITMAP_BITS)
		return;
	if (end > CLONE_BITMAP_BITS)
		end = CLONE_BITMAP_BITS;

	for (word = start >> 6; word < ((end - 1) >> 6) + 1; word++) {
		first_bit = (word == (start >> 6)) ? (start & 63) : 0;
		last_bit = (word == ((end - 1) >> 6)) ? ((end - 1) & 63) : 63;

		if (first_bit == 0 && last_bit == 63) {
			mask = ~0ULL;
		} else {
			mask = ((1ULL << (last_bit - first_bit + 1)) - 1) << first_bit;
		}
		bm->words[word] |= mask;
	}
}

/*
 * Clear a range of bits [start, start+count).
 */
static inline void clone_batch_bitmap_clear_range(clone_batch_bitmap_t *bm, int start, int count)
{
	int end = start + count;
	int word, first_bit, last_bit;
	uint64_t mask;

	if (count <= 0 || start >= CLONE_BITMAP_BITS)
		return;
	if (end > CLONE_BITMAP_BITS)
		end = CLONE_BITMAP_BITS;

	for (word = start >> 6; word < ((end - 1) >> 6) + 1; word++) {
		first_bit = (word == (start >> 6)) ? (start & 63) : 0;
		last_bit = (word == ((end - 1) >> 6)) ? ((end - 1) & 63) : 63;

		if (first_bit == 0 && last_bit == 63) {
			mask = ~0ULL;
		} else {
			mask = ((1ULL << (last_bit - first_bit + 1)) - 1) << first_bit;
		}
		bm->words[word] &= ~mask;
	}
}

/*
 * Check if bitmap is full up to 'limit' bits (for partial batches).
 * Returns 1 if all bits [0, limit) are set.
 */
static inline int clone_batch_bitmap_is_full_upto(const clone_batch_bitmap_t *bm, int limit)
{
	int full_words = limit >> 6;
	int remaining_bits = limit & 63;
	int i;

	for (i = 0; i < full_words; i++) {
		if (bm->words[i] != ~0ULL)
			return 0;
	}

	if (remaining_bits > 0) {
		uint64_t mask = (1ULL << remaining_bits) - 1;
		if ((bm->words[full_words] & mask) != mask)
			return 0;
	}

	return 1;
}

/*
 * Macro for iterating over all set bits.
 * Usage:
 *   int idx;
 *   CLONE_BATCH_BITMAP_FOR_EACH_SET(bm, idx) {
 *       // process bit at index idx
 *   }
 */
#define CLONE_BATCH_BITMAP_FOR_EACH_SET(bm, idx) \
	for ((idx) = clone_batch_bitmap_next_set((bm), 0); \
	     (idx) >= 0; \
	     (idx) = clone_batch_bitmap_next_set((bm), (idx) + 1))

#endif /* __CR_CLONE_BATCH_BITMAP_H__ */
