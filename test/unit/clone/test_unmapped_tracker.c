#include <pthread.h>

#include "test_harness.h"
#include "page.h"
#include "clone/unmapped-tracker.h"

static void test_init_destroy(void)
{
	int rc = unmapped_tracker_init();
	TEST_ASSERT_EQ(rc, 0, "init succeeds");

	/* Double init is safe */
	rc = unmapped_tracker_init();
	TEST_ASSERT_EQ(rc, 0, "double init returns 0");

	unmapped_tracker_destroy();
}

static void test_mark_single_page(void)
{
	unmapped_tracker_init();

	unsigned long addr = 0x7f0000001000UL;
	unmapped_tracker_mark_range(addr, PAGE_SIZE);

	TEST_ASSERT(unmapped_tracker_is_unmapped(addr), "marked page is unmapped");
	TEST_ASSERT(!unmapped_tracker_is_unmapped(addr + PAGE_SIZE), "next page not unmapped");
	TEST_ASSERT(!unmapped_tracker_is_unmapped(addr - PAGE_SIZE), "prev page not unmapped");

	unmapped_tracker_destroy();
}

static void test_mark_range(void)
{
	unmapped_tracker_init();

	unsigned long start = 0x7f0000010000UL;
	int nr_pages = 100;
	unsigned long len = nr_pages * PAGE_SIZE;

	unmapped_tracker_mark_range(start, len);

	for (int i = 0; i < nr_pages; i++) {
		TEST_ASSERT(unmapped_tracker_is_unmapped(start + i * PAGE_SIZE),
			    "page in range is unmapped");
	}
	TEST_ASSERT(!unmapped_tracker_is_unmapped(start - PAGE_SIZE), "before range not unmapped");
	TEST_ASSERT(!unmapped_tracker_is_unmapped(start + len), "after range not unmapped");

	unmapped_tracker_destroy();
}

static void test_clear(void)
{
	unmapped_tracker_init();

	unsigned long addr = 0x7f0000002000UL;
	unmapped_tracker_mark_range(addr, PAGE_SIZE);
	TEST_ASSERT(unmapped_tracker_is_unmapped(addr), "marked");

	unmapped_tracker_clear(addr);
	TEST_ASSERT(!unmapped_tracker_is_unmapped(addr), "cleared");

	unmapped_tracker_destroy();
}

static void test_not_marked_returns_false(void)
{
	unmapped_tracker_init();

	TEST_ASSERT(!unmapped_tracker_is_unmapped(0x7f0000099000UL), "unmarked page returns false");

	unmapped_tracker_destroy();
}

static void test_operations_before_init(void)
{
	/* These should not crash even though tracker is not initialized */
	TEST_ASSERT(!unmapped_tracker_is_unmapped(0x1000), "is_unmapped before init = false");
	unmapped_tracker_mark_range(0x1000, PAGE_SIZE);
	unmapped_tracker_clear(0x1000);
	unmapped_tracker_destroy();
}

static void test_hash_collision(void)
{
	unmapped_tracker_init();

	/*
	 * Pages that hash to the same bucket (hash = (vaddr >> 12) & 0xFFFF).
	 * Two addresses with same lower 28 bits (after >> 12 that's 16 bits):
	 * addr1 = 0x10000000 and addr2 = 0x20000000 differ only in bits above bucket mask.
	 * Actually: (0x10000000 >> 12) & 0xFFFF = 0x0000
	 *           (0x10010000 >> 12) & 0xFFFF = 0x0010
	 * To get same hash: need (addr >> 12) & 0xFFFF to match.
	 * 0x7f0000001000 >> 12 = 0x7f0000001, & 0xFFFF = 0x0001
	 * 0x7f0100001000 >> 12 = 0x7f0100001, & 0xFFFF = 0x0001  <- same!
	 */
	unsigned long addr1 = 0x7f0000001000UL;
	unsigned long addr2 = 0x7f0100001000UL;

	unmapped_tracker_mark_range(addr1, PAGE_SIZE);
	unmapped_tracker_mark_range(addr2, PAGE_SIZE);

	TEST_ASSERT(unmapped_tracker_is_unmapped(addr1), "collision addr1 found");
	TEST_ASSERT(unmapped_tracker_is_unmapped(addr2), "collision addr2 found");

	unmapped_tracker_clear(addr1);
	TEST_ASSERT(!unmapped_tracker_is_unmapped(addr1), "addr1 cleared");
	TEST_ASSERT(unmapped_tracker_is_unmapped(addr2), "addr2 still present");

	unmapped_tracker_destroy();
}

#define MT_NUM_THREADS 4
#define MT_PAGES_PER_THREAD 1000

static void *mt_marker(void *arg)
{
	int id = (int)(long)arg;
	unsigned long base = 0x7f0000000000UL + (unsigned long)id * MT_PAGES_PER_THREAD * PAGE_SIZE * 2;

	for (int i = 0; i < MT_PAGES_PER_THREAD; i++)
		unmapped_tracker_mark_range(base + (unsigned long)i * PAGE_SIZE, PAGE_SIZE);

	return NULL;
}

static void test_multi_threaded(void)
{
	unmapped_tracker_init();

	pthread_t threads[MT_NUM_THREADS];
	for (int i = 0; i < MT_NUM_THREADS; i++)
		pthread_create(&threads[i], NULL, mt_marker, (void *)(long)i);
	for (int i = 0; i < MT_NUM_THREADS; i++)
		pthread_join(threads[i], NULL);

	/* Verify all pages were marked */
	int found = 0;
	for (int id = 0; id < MT_NUM_THREADS; id++) {
		unsigned long base = 0x7f0000000000UL + (unsigned long)id * MT_PAGES_PER_THREAD * PAGE_SIZE * 2;
		for (int i = 0; i < MT_PAGES_PER_THREAD; i++) {
			if (unmapped_tracker_is_unmapped(base + (unsigned long)i * PAGE_SIZE))
				found++;
		}
	}
	TEST_ASSERT_EQ(found, MT_NUM_THREADS * MT_PAGES_PER_THREAD, "all MT pages found");

	unmapped_tracker_destroy();
}

static void test_large_range_unrolled_nodes(void)
{
	unmapped_tracker_init();

	/* Mark 64 pages - should fill 2 unrolled nodes (32 entries each) */
	unsigned long start = 0x7f0000100000UL;
	unmapped_tracker_mark_range(start, 64 * PAGE_SIZE);

	for (int i = 0; i < 64; i++)
		TEST_ASSERT(unmapped_tracker_is_unmapped(start + (unsigned long)i * PAGE_SIZE),
			    "large range page found");

	unmapped_tracker_destroy();
}

int main(void)
{
	printf("=== Unmapped Tracker Tests ===\n");
	RUN_TEST(test_init_destroy);
	RUN_TEST(test_mark_single_page);
	RUN_TEST(test_mark_range);
	RUN_TEST(test_clear);
	RUN_TEST(test_not_marked_returns_false);
	RUN_TEST(test_operations_before_init);
	RUN_TEST(test_hash_collision);
	RUN_TEST(test_multi_threaded);
	RUN_TEST(test_large_range_unrolled_nodes);
	TEST_SUMMARY();
}
