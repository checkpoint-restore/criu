#include "test_harness.h"
#include "clone/clone-batch-bitmap.h"

static void test_zero_and_fill(void)
{
	clone_batch_bitmap_t bm;

	clone_batch_bitmap_zero(&bm);
	TEST_ASSERT(clone_batch_bitmap_is_empty(&bm), "zero produces empty");
	TEST_ASSERT(!clone_batch_bitmap_is_full(&bm), "zero is not full");

	clone_batch_bitmap_fill(&bm);
	TEST_ASSERT(clone_batch_bitmap_is_full(&bm), "fill produces full");
	TEST_ASSERT(!clone_batch_bitmap_is_empty(&bm), "fill is not empty");
}

static void test_set_clear_test(void)
{
	clone_batch_bitmap_t bm;
	int boundaries[] = {0, 63, 64, 127, 128, 191, 192, 255};

	clone_batch_bitmap_zero(&bm);

	for (int i = 0; i < 8; i++) {
		clone_batch_bitmap_set(&bm, boundaries[i]);
		TEST_ASSERT(clone_batch_bitmap_test(&bm, boundaries[i]), "set bit visible");
	}
	TEST_ASSERT_EQ(clone_batch_bitmap_popcount(&bm), 8, "8 bits set");

	for (int i = 0; i < 8; i++) {
		clone_batch_bitmap_clear(&bm, boundaries[i]);
		TEST_ASSERT(!clone_batch_bitmap_test(&bm, boundaries[i]), "clear bit gone");
	}
	TEST_ASSERT(clone_batch_bitmap_is_empty(&bm), "all cleared = empty");
}

static void test_popcount(void)
{
	clone_batch_bitmap_t bm;

	clone_batch_bitmap_zero(&bm);
	TEST_ASSERT_EQ(clone_batch_bitmap_popcount(&bm), 0, "empty popcount=0");

	for (int i = 0; i < 256; i++) {
		clone_batch_bitmap_set(&bm, i);
		TEST_ASSERT_EQ(clone_batch_bitmap_popcount(&bm), i + 1, "popcount increments");
	}
}

static void test_next_set(void)
{
	clone_batch_bitmap_t bm;

	clone_batch_bitmap_zero(&bm);
	TEST_ASSERT_EQ(clone_batch_bitmap_next_set(&bm, 0), -1, "empty has no bits");

	clone_batch_bitmap_set(&bm, 5);
	clone_batch_bitmap_set(&bm, 100);
	clone_batch_bitmap_set(&bm, 200);

	TEST_ASSERT_EQ(clone_batch_bitmap_next_set(&bm, 0), 5, "first set at 5");
	TEST_ASSERT_EQ(clone_batch_bitmap_next_set(&bm, 6), 100, "next set at 100");
	TEST_ASSERT_EQ(clone_batch_bitmap_next_set(&bm, 101), 200, "next set at 200");
	TEST_ASSERT_EQ(clone_batch_bitmap_next_set(&bm, 201), -1, "no more bits");
}

static void test_set_range(void)
{
	clone_batch_bitmap_t bm;

	/* Range within one word */
	clone_batch_bitmap_zero(&bm);
	clone_batch_bitmap_set_range(&bm, 10, 20);
	TEST_ASSERT_EQ(clone_batch_bitmap_popcount(&bm), 20, "range of 20");
	TEST_ASSERT(clone_batch_bitmap_test(&bm, 10), "range start set");
	TEST_ASSERT(clone_batch_bitmap_test(&bm, 29), "range end set");
	TEST_ASSERT(!clone_batch_bitmap_test(&bm, 9), "before range clear");
	TEST_ASSERT(!clone_batch_bitmap_test(&bm, 30), "after range clear");

	/* Range spanning word boundaries */
	clone_batch_bitmap_zero(&bm);
	clone_batch_bitmap_set_range(&bm, 60, 10);
	TEST_ASSERT_EQ(clone_batch_bitmap_popcount(&bm), 10, "cross-word range");
	TEST_ASSERT(clone_batch_bitmap_test(&bm, 60), "cross start");
	TEST_ASSERT(clone_batch_bitmap_test(&bm, 69), "cross end");

	/* Full range */
	clone_batch_bitmap_zero(&bm);
	clone_batch_bitmap_set_range(&bm, 0, 256);
	TEST_ASSERT(clone_batch_bitmap_is_full(&bm), "full range = full");
}

static void test_clear_range(void)
{
	clone_batch_bitmap_t bm;

	clone_batch_bitmap_fill(&bm);
	clone_batch_bitmap_clear_range(&bm, 64, 64);
	TEST_ASSERT_EQ(clone_batch_bitmap_popcount(&bm), 192, "cleared 64 bits");
	TEST_ASSERT(!clone_batch_bitmap_test(&bm, 64), "cleared start");
	TEST_ASSERT(!clone_batch_bitmap_test(&bm, 127), "cleared end");
	TEST_ASSERT(clone_batch_bitmap_test(&bm, 63), "before range untouched");
	TEST_ASSERT(clone_batch_bitmap_test(&bm, 128), "after range untouched");
}

static void test_and_or_not(void)
{
	clone_batch_bitmap_t a, b, result;

	clone_batch_bitmap_zero(&a);
	clone_batch_bitmap_zero(&b);
	clone_batch_bitmap_set_range(&a, 0, 128);
	clone_batch_bitmap_set_range(&b, 64, 128);

	clone_batch_bitmap_and(&result, &a, &b);
	TEST_ASSERT_EQ(clone_batch_bitmap_popcount(&result), 64, "AND overlap");
	TEST_ASSERT(clone_batch_bitmap_test(&result, 64), "AND bit 64");
	TEST_ASSERT(clone_batch_bitmap_test(&result, 127), "AND bit 127");
	TEST_ASSERT(!clone_batch_bitmap_test(&result, 63), "AND not bit 63");

	clone_batch_bitmap_or(&result, &a, &b);
	TEST_ASSERT_EQ(clone_batch_bitmap_popcount(&result), 192, "OR union");

	clone_batch_bitmap_not(&result, &a);
	TEST_ASSERT_EQ(clone_batch_bitmap_popcount(&result), 128, "NOT flips");
}

static void test_mask(void)
{
	clone_batch_bitmap_t bm;

	clone_batch_bitmap_fill(&bm);
	clone_batch_bitmap_mask(&bm, 100);
	TEST_ASSERT_EQ(clone_batch_bitmap_popcount(&bm), 100, "mask to 100");
	TEST_ASSERT(clone_batch_bitmap_test(&bm, 99), "bit 99 still set");
	TEST_ASSERT(!clone_batch_bitmap_test(&bm, 100), "bit 100 cleared");
}

static void test_is_full_upto(void)
{
	clone_batch_bitmap_t bm;

	clone_batch_bitmap_zero(&bm);
	clone_batch_bitmap_set_range(&bm, 0, 64);
	TEST_ASSERT(clone_batch_bitmap_is_full_upto(&bm, 64), "full up to 64");
	TEST_ASSERT(!clone_batch_bitmap_is_full_upto(&bm, 65), "not full to 65");
	TEST_ASSERT(clone_batch_bitmap_is_full_upto(&bm, 1), "full up to 1");
}

static void test_for_each_set_macro(void)
{
	clone_batch_bitmap_t bm;
	int idx, count = 0;
	int expected[] = {3, 77, 200};

	clone_batch_bitmap_zero(&bm);
	clone_batch_bitmap_set(&bm, 3);
	clone_batch_bitmap_set(&bm, 77);
	clone_batch_bitmap_set(&bm, 200);

	CLONE_BATCH_BITMAP_FOR_EACH_SET(&bm, idx) {
		TEST_ASSERT(count < 3, "not too many iterations");
		if (count < 3)
			TEST_ASSERT_EQ(idx, expected[count], "correct iteration order");
		count++;
	}
	TEST_ASSERT_EQ(count, 3, "iterated all set bits");
}

static void test_edge_cases(void)
{
	clone_batch_bitmap_t bm;

	/* set_range with count=0 should be no-op */
	clone_batch_bitmap_zero(&bm);
	clone_batch_bitmap_set_range(&bm, 50, 0);
	TEST_ASSERT(clone_batch_bitmap_is_empty(&bm), "zero-count range is nop");

	/* set_range beyond limit - clamped to 256 */
	clone_batch_bitmap_zero(&bm);
	clone_batch_bitmap_set_range(&bm, 250, 100);
	TEST_ASSERT_EQ(clone_batch_bitmap_popcount(&bm), 6, "clamped to 256");

	/* next_set from 256+ */
	TEST_ASSERT_EQ(clone_batch_bitmap_next_set(&bm, 256), -1, "past end = -1");
}

static void test_copy(void)
{
	clone_batch_bitmap_t src, dst;

	clone_batch_bitmap_zero(&src);
	clone_batch_bitmap_set(&src, 42);
	clone_batch_bitmap_set(&src, 200);

	clone_batch_bitmap_copy(&dst, &src);
	TEST_ASSERT(clone_batch_bitmap_test(&dst, 42), "copy bit 42");
	TEST_ASSERT(clone_batch_bitmap_test(&dst, 200), "copy bit 200");
	TEST_ASSERT_EQ(clone_batch_bitmap_popcount(&dst), 2, "copy popcount");
}

int main(void)
{
	printf("=== CLONE Batch Bitmap Tests ===\n");
	RUN_TEST(test_zero_and_fill);
	RUN_TEST(test_set_clear_test);
	RUN_TEST(test_popcount);
	RUN_TEST(test_next_set);
	RUN_TEST(test_set_range);
	RUN_TEST(test_clear_range);
	RUN_TEST(test_and_or_not);
	RUN_TEST(test_mask);
	RUN_TEST(test_is_full_upto);
	RUN_TEST(test_for_each_set_macro);
	RUN_TEST(test_edge_cases);
	RUN_TEST(test_copy);
	TEST_SUMMARY();
}
