#include "test_harness.h"
#include "clone/clone-batch-bitmap.h"

/* clone-conf.h sets CLONE_BATCH_PAGES = 256 = the bitmap width (CLONE_BITMAP_BITS).
 * The unit harness compiles only the header, so derive it from the header. */
#ifndef CLONE_BATCH_PAGES
#define CLONE_BATCH_PAGES CLONE_BITMAP_BITS
#endif

/*
 * Compute pool pages freed by the correct algorithm (snapshot before clear).
 * free_bm = ~initial_bitmap | page_bitmap_before_clear
 */
static int free_count(const clone_batch_bitmap_t *initial_bitmap,
                      const clone_batch_bitmap_t *page_bitmap_before)
{
        clone_batch_bitmap_t free_bm;

        clone_batch_bitmap_not(&free_bm, initial_bitmap);
        clone_batch_bitmap_mask(&free_bm, CLONE_BATCH_PAGES);
        clone_batch_bitmap_or(&free_bm, &free_bm, page_bitmap_before);
        return clone_batch_bitmap_popcount(&free_bm);
}

/*
 * Scenario: a batch with CLONE_BATCH_PAGES pool slots. initial_bitmap marks
 * pages that carried data (were "owned"). No page faults happened, so
 * page_bitmap == initial_bitmap at unmap time. Then the WHOLE batch is unmapped.
 *
 * Regression check: every pool slot must be freed (owned pages via page_bitmap,
 * unused slots via ~initial_bitmap).
 */
static void test_full_unmap_frees_all_pool_pages(void)
{
        clone_batch_bitmap_t initial, page_now;
        int n_owned = 40; /* pages that carried data */
        int i, freed;

        clone_batch_bitmap_zero(&initial);
        for (i = 0; i < n_owned; i++)
                clone_batch_bitmap_set(&initial, i);
        page_now = initial; /* no page faults consumed any */

        freed = free_count(&initial, &page_now);

        TEST_ASSERT_EQ(freed, CLONE_BATCH_PAGES,
                       "full unmap frees every pool slot");
}

/*
 * Partial scenario: fully owned batch, check that free_count would free all
 * slots (sanity check for the mask math).
 */
static void test_fully_owned_batch(void)
{
        clone_batch_bitmap_t initial, page_now;
        int i, freed;

        clone_batch_bitmap_zero(&initial);
        for (i = 0; i < CLONE_BATCH_PAGES; i++)
                clone_batch_bitmap_set(&initial, i); /* fully owned batch */
        page_now = initial;

        freed = free_count(&initial, &page_now);

        TEST_ASSERT_EQ(freed, CLONE_BATCH_PAGES,
                       "fully owned batch frees all slots");
}

int main(void)
{
        printf("=== remove_range pool-page leak regression ===\n");
        RUN_TEST(test_full_unmap_frees_all_pool_pages);
        RUN_TEST(test_fully_owned_batch);
        TEST_SUMMARY();
}