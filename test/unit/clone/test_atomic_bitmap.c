#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include "test_harness.h"
#include "clone/atomic-bitmap.h"

static void test_set_and_test(void)
{
	uint8_t bitmap[16];
	memset(bitmap, 0, sizeof(bitmap));

	atomic_bitmap_set(bitmap, 0);
	TEST_ASSERT(atomic_bitmap_test(bitmap, 0), "bit 0 set");
	TEST_ASSERT(!atomic_bitmap_test(bitmap, 1), "bit 1 not set");

	atomic_bitmap_set(bitmap, 7);
	TEST_ASSERT(atomic_bitmap_test(bitmap, 7), "bit 7 set");

	atomic_bitmap_set(bitmap, 8);
	TEST_ASSERT(atomic_bitmap_test(bitmap, 8), "bit 8 set (byte boundary)");

	atomic_bitmap_set(bitmap, 127);
	TEST_ASSERT(atomic_bitmap_test(bitmap, 127), "bit 127 set");
}

static void test_clear(void)
{
	uint8_t bitmap[16];
	memset(bitmap, 0xFF, sizeof(bitmap));

	atomic_bitmap_clear(bitmap, 0);
	TEST_ASSERT(!atomic_bitmap_test(bitmap, 0), "bit 0 cleared");
	TEST_ASSERT(atomic_bitmap_test(bitmap, 1), "bit 1 still set");

	atomic_bitmap_clear(bitmap, 7);
	TEST_ASSERT(!atomic_bitmap_test(bitmap, 7), "bit 7 cleared");
	TEST_ASSERT(atomic_bitmap_test(bitmap, 6), "bit 6 still set");

	atomic_bitmap_clear(bitmap, 8);
	TEST_ASSERT(!atomic_bitmap_test(bitmap, 8), "bit 8 cleared");
	TEST_ASSERT(atomic_bitmap_test(bitmap, 9), "bit 9 still set");
}

static void test_test_and_set(void)
{
	uint8_t bitmap[16];
	memset(bitmap, 0, sizeof(bitmap));

	bool was_set = atomic_bitmap_test_and_set(bitmap, 42);
	TEST_ASSERT(!was_set, "first test_and_set returns false");
	TEST_ASSERT(atomic_bitmap_test(bitmap, 42), "bit is now set");

	was_set = atomic_bitmap_test_and_set(bitmap, 42);
	TEST_ASSERT(was_set, "second test_and_set returns true");
	TEST_ASSERT(atomic_bitmap_test(bitmap, 42), "bit still set");
}

static void test_byte_boundaries(void)
{
	uint8_t bitmap[4];
	memset(bitmap, 0, sizeof(bitmap));

	/* Set bits at every byte boundary */
	for (int i = 0; i < 32; i++) {
		atomic_bitmap_set(bitmap, i);
	}

	/* Verify all set */
	for (int i = 0; i < 32; i++) {
		TEST_ASSERT(atomic_bitmap_test(bitmap, i), "all 32 bits set");
	}

	/* Bitmap should be all 0xFF */
	for (int i = 0; i < 4; i++) {
		TEST_ASSERT_EQ(bitmap[i], 0xFF, "byte all ones");
	}
}

static void test_alloc_size_macro(void)
{
	TEST_ASSERT_EQ(BITMAP_ALLOC_SIZE(1), 1, "1 page = 1 byte");
	TEST_ASSERT_EQ(BITMAP_ALLOC_SIZE(7), 1, "7 pages = 1 byte");
	TEST_ASSERT_EQ(BITMAP_ALLOC_SIZE(8), 1, "8 pages = 1 byte");
	TEST_ASSERT_EQ(BITMAP_ALLOC_SIZE(9), 2, "9 pages = 2 bytes");
	TEST_ASSERT_EQ(BITMAP_ALLOC_SIZE(16), 2, "16 pages = 2 bytes");
	TEST_ASSERT_EQ(BITMAP_ALLOC_SIZE(256), 32, "256 pages = 32 bytes");
	TEST_ASSERT_EQ(BITMAP_ALLOC_SIZE(1024), 128, "1024 pages = 128 bytes");
}

static void test_nonatomic_variants(void)
{
	unsigned char bitmap[16];
	_Atomic unsigned long counter = 0;
	memset(bitmap, 0, sizeof(bitmap));

	bitmap_set_nonatomic(bitmap, 5, &counter);
	TEST_ASSERT(bitmap_test_nonatomic(bitmap, 5), "nonatomic set+test");
	TEST_ASSERT_EQ(counter, 1, "counter incremented");

	bitmap_set_nonatomic(bitmap, 10, &counter);
	TEST_ASSERT_EQ(counter, 2, "counter incremented again");

	bitmap_clear_nonatomic(bitmap, 5, &counter);
	TEST_ASSERT(!bitmap_test_nonatomic(bitmap, 5), "nonatomic clear");
	TEST_ASSERT_EQ(counter, 1, "counter decremented");

	/* NULL counter */
	bitmap_set_nonatomic(bitmap, 20, NULL);
	TEST_ASSERT(bitmap_test_nonatomic(bitmap, 20), "set with NULL counter");
}

#define MT_BITMAP_SIZE 1024
#define MT_THREADS 4
#define MT_BITS_PER_THREAD 256

static uint8_t mt_bitmap[BITMAP_ALLOC_SIZE(MT_BITMAP_SIZE)];

static void *mt_setter(void *arg)
{
	int id = (int)(long)arg;
	int start = id * MT_BITS_PER_THREAD;

	for (int i = 0; i < MT_BITS_PER_THREAD; i++)
		atomic_bitmap_set(mt_bitmap, start + i);

	return NULL;
}

static void test_concurrent_set(void)
{
	memset(mt_bitmap, 0, sizeof(mt_bitmap));

	pthread_t threads[MT_THREADS];
	for (int i = 0; i < MT_THREADS; i++)
		pthread_create(&threads[i], NULL, mt_setter, (void *)(long)i);
	for (int i = 0; i < MT_THREADS; i++)
		pthread_join(threads[i], NULL);

	/* Verify all bits were set */
	int set_count = 0;
	for (int i = 0; i < MT_THREADS * MT_BITS_PER_THREAD; i++) {
		if (atomic_bitmap_test(mt_bitmap, i))
			set_count++;
	}
	TEST_ASSERT_EQ(set_count, MT_THREADS * MT_BITS_PER_THREAD, "all MT bits set");
}

static int tas_winners;

static void *mt_test_and_set_worker(void *arg)
{
	(void)arg;
	/* All threads race to test_and_set the same bit */
	for (int i = 0; i < 1000; i++) {
		bool was_set = atomic_bitmap_test_and_set(mt_bitmap, 0);
		if (!was_set)
			__atomic_fetch_add(&tas_winners, 1, __ATOMIC_RELAXED);
		/* Reset for next iteration */
		atomic_bitmap_clear(mt_bitmap, 0);
	}
	return NULL;
}

static void test_concurrent_test_and_set(void)
{
	memset(mt_bitmap, 0, sizeof(mt_bitmap));
	__atomic_store_n(&tas_winners, 0, __ATOMIC_RELAXED);

	pthread_t threads[MT_THREADS];
	for (int i = 0; i < MT_THREADS; i++)
		pthread_create(&threads[i], NULL, mt_test_and_set_worker, NULL);
	for (int i = 0; i < MT_THREADS; i++)
		pthread_join(threads[i], NULL);

	/* At least some threads should have won the race */
	int winners = __atomic_load_n(&tas_winners, __ATOMIC_RELAXED);
	TEST_ASSERT(winners > 0, "some threads won test_and_set races");
	/* At most threads * iterations total wins possible */
	TEST_ASSERT(winners <= MT_THREADS * 1000, "bounded winners");
}

int main(void)
{
	printf("=== Atomic Bitmap Tests ===\n");
	RUN_TEST(test_set_and_test);
	RUN_TEST(test_clear);
	RUN_TEST(test_test_and_set);
	RUN_TEST(test_byte_boundaries);
	RUN_TEST(test_alloc_size_macro);
	RUN_TEST(test_nonatomic_variants);
	RUN_TEST(test_concurrent_set);
	RUN_TEST(test_concurrent_test_and_set);
	TEST_SUMMARY();
}
