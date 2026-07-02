#include <pthread.h>
#include <string.h>
#include <stdint.h>

#include "test_harness.h"
#include "page.h"
#include "clone/page-pool.h"
#include "clone/clone-conf.h"

static void test_thread_init(void)
{
	int rc = page_pool_thread_init(0);
	TEST_ASSERT_EQ(rc, 0, "thread 0 init succeeds");

	/* Double init is safe */
	rc = page_pool_thread_init(0);
	TEST_ASSERT_EQ(rc, 0, "double init returns 0");
}

static void test_get_returns_aligned(void)
{
	page_pool_thread_init(1);

	void *page = page_pool_get_pages(1, 1);
	TEST_ASSERT(page != NULL, "get returns non-NULL");
	TEST_ASSERT_EQ((unsigned long)page & (PAGE_SIZE - 1), 0, "page is PAGE_SIZE aligned");

	/* Write to it to verify it's usable memory */
	memset(page, 0xAB, PAGE_SIZE);

	page_pool_put(page);
}

static void test_get_pages_contiguous(void)
{
	page_pool_thread_init(2);

	int nr_pages = 16;
	void *pages = page_pool_get_pages(2, nr_pages);
	TEST_ASSERT(pages != NULL, "get_pages returns non-NULL");
	TEST_ASSERT_EQ((unsigned long)pages & (PAGE_SIZE - 1), 0, "pages aligned");

	/* Verify all pages are writable and contiguous */
	for (int i = 0; i < nr_pages; i++) {
		void *p = (char *)pages + i * PAGE_SIZE;
		memset(p, i & 0xFF, PAGE_SIZE);
	}

	/* Free each page individually */
	for (int i = 0; i < nr_pages; i++)
		page_pool_put((char *)pages + i * PAGE_SIZE);
}

static void test_put_refcount(void)
{
	page_pool_thread_init(4);

	/* Allocate several pages from same chunk, free them all */
	void *pages[64];
	for (int i = 0; i < 64; i++)
		pages[i] = page_pool_get_pages(4, 1);

	/* All from same chunk - verify chunk_id matches */
	int first_id = page_pool_get_chunk_id(pages[0]);
	TEST_ASSERT(first_id >= 0, "chunk_id valid");

	for (int i = 1; i < 64; i++) {
		int id = page_pool_get_chunk_id(pages[i]);
		TEST_ASSERT_EQ(id, first_id, "all pages from same chunk");
	}

	/* Free them all */
	for (int i = 0; i < 64; i++)
		page_pool_put(pages[i]);
}

#define MT_POOL_THREADS 4
#define MT_POOL_ALLOCS  1000

static void *pool_allocator(void *arg)
{
	int tid = (int)(long)arg;
	page_pool_thread_init(tid + 10);

	void *pages[MT_POOL_ALLOCS];
	for (int i = 0; i < MT_POOL_ALLOCS; i++)
		pages[i] = page_pool_get_pages(tid + 10, 1);

	/* Write unique pattern to detect overlaps */
	for (int i = 0; i < MT_POOL_ALLOCS; i++)
		memset(pages[i], tid + 1, PAGE_SIZE);

	/* Verify patterns are intact */
	for (int i = 0; i < MT_POOL_ALLOCS; i++) {
		unsigned char *p = pages[i];
		for (int j = 0; j < 16; j++) {
			if (p[j] != (unsigned char)(tid + 1)) {
				return (void *)1L;
			}
		}
	}

	/* Free */
	for (int i = 0; i < MT_POOL_ALLOCS; i++)
		page_pool_put(pages[i]);

	return NULL;
}

static void test_multi_threaded_no_overlap(void)
{
	pthread_t threads[MT_POOL_THREADS];
	void *ret;

	for (int i = 0; i < MT_POOL_THREADS; i++)
		pthread_create(&threads[i], NULL, pool_allocator, (void *)(long)i);

	int all_ok = 1;
	for (int i = 0; i < MT_POOL_THREADS; i++) {
		pthread_join(threads[i], &ret);
		if (ret != NULL)
			all_ok = 0;
	}
	TEST_ASSERT(all_ok, "no overlap between threads");
}

static void test_nr_chunks(void)
{
	int nr = page_pool_get_nr_chunks();
	TEST_ASSERT(nr > 0, "at least one chunk allocated");
}

/*
 * Regression test for use-after-free bug:
 *
 * Producer allocates pages from chunk X, hands them to consumer threads.
 * Consumers free ALL pages before the producer allocates again.
 * Without the producer-hold fix, chunk X gets munmap'd while
 * pool->current_chunk still points to it → SIGSEGV on next get.
 *
 * The fix adds a "producer reference" that keeps the chunk alive
 * until the producer swaps to a new chunk.
 */

#define UAF_PRODUCER_TID    5
#define UAF_CONSUMER_THREADS 4
#define UAF_ROUNDS           10
#define UAF_PAGES_PER_ROUND  CLONE_ALLOC_BATCH

struct uaf_work {
	void *pages[UAF_PAGES_PER_ROUND];
	int count;
	int ready;
	int done;
};

static struct uaf_work uaf_batches[UAF_ROUNDS];

static void *uaf_consumer(void *arg)
{
	int id = (int)(long)arg;

	for (int round = id; round < UAF_ROUNDS; round += UAF_CONSUMER_THREADS) {
		/* Wait for producer to fill this batch */
		while (!__atomic_load_n(&uaf_batches[round].ready, __ATOMIC_ACQUIRE))
			;

		/* Free all pages immediately — this may drop chunk refcount to 0 */
		for (int i = 0; i < uaf_batches[round].count; i++)
			page_pool_put(uaf_batches[round].pages[i]);

		__atomic_store_n(&uaf_batches[round].done, 1, __ATOMIC_RELEASE);
	}
	return NULL;
}

static void test_producer_consumer_use_after_free(void)
{
	page_pool_thread_init(UAF_PRODUCER_TID);
	memset(uaf_batches, 0, sizeof(uaf_batches));

	/* Start consumers */
	pthread_t consumers[UAF_CONSUMER_THREADS];
	for (int i = 0; i < UAF_CONSUMER_THREADS; i++)
		pthread_create(&consumers[i], NULL, uaf_consumer, (void *)(long)i);

	for (int round = 0; round < UAF_ROUNDS; round++) {
		/* Producer allocates a batch */
		void *batch = page_pool_get_pages(UAF_PRODUCER_TID, UAF_PAGES_PER_ROUND);
		TEST_ASSERT(batch != NULL, "producer get_pages non-NULL");

		for (int i = 0; i < UAF_PAGES_PER_ROUND; i++)
			uaf_batches[round].pages[i] = (char *)batch + i * PAGE_SIZE;
		uaf_batches[round].count = UAF_PAGES_PER_ROUND;

		/* Signal consumer to free these pages */
		__atomic_store_n(&uaf_batches[round].ready, 1, __ATOMIC_RELEASE);

		/* Wait for consumer to finish freeing before next round.		
		 * all refs gone while we still hold current_chunk. */
		while (!__atomic_load_n(&uaf_batches[round].done, __ATOMIC_ACQUIRE))
			;
	}

	/* If we get here without SIGSEGV, the producer-hold fix works */
	for (int i = 0; i < UAF_CONSUMER_THREADS; i++)
		pthread_join(consumers[i], NULL);

	TEST_ASSERT(1, "no use-after-free crash");
}

/*
 * Test chunk exhaustion: allocate until the current chunk is full,
 * then verify the producer seamlessly swaps to a new chunk and
 * can keep allocating.
 */
static void test_chunk_exhaustion_and_swap(void)
{
	int tid = 6;
	page_pool_thread_init(tid);

	int initial_chunks = page_pool_get_nr_chunks();

	/* Allocate pages until we exhaust the current chunk and force a swap.
	 * CLONE_PAGES_PER_CHUNK - 1 usable pages per chunk (page 0 is header). */
	int alloc_count = CLONE_PAGES_PER_CHUNK; /* Slightly more than fits */
	void **pages = malloc(alloc_count * sizeof(void *));
	TEST_ASSERT(pages != NULL, "malloc for page array");

	for (int i = 0; i < alloc_count; i++) {
		pages[i] = page_pool_get_pages(tid, 1);
		TEST_ASSERT(pages[i] != NULL, "get succeeds after exhaustion");
	}

	/* Should have allocated at least one more chunk */
	int final_chunks = page_pool_get_nr_chunks();
	TEST_ASSERT(final_chunks > initial_chunks, "new chunk allocated on exhaustion");

	/* Free all */
	for (int i = 0; i < alloc_count; i++)
		page_pool_put(pages[i]);

	free(pages);
}

/*
 * Simulate the real CLONE pattern: producer allocates batches in a loop,
 * multiple consumer threads free pages concurrently. Producer must
 * never crash even though chunks are being freed underneath.
 */

#define PIPELINE_PRODUCER_TID 7
#define PIPELINE_CONSUMERS    4
#define PIPELINE_BATCHES      50
#define PIPELINE_BATCH_PAGES  64

struct pipeline_slot {
	void *pages[PIPELINE_BATCH_PAGES];
	int count;
	volatile int ready;
	volatile int consumed;
};

static struct pipeline_slot pipeline[PIPELINE_BATCHES];
static volatile int pipeline_producer_done;

static void *pipeline_consumer(void *arg)
{
	int id = (int)(long)arg;

	for (int slot = id; slot < PIPELINE_BATCHES; slot += PIPELINE_CONSUMERS) {
		while (!pipeline[slot].ready)
			;
		for (int i = 0; i < pipeline[slot].count; i++)
			page_pool_put(pipeline[slot].pages[i]);
		pipeline[slot].consumed = 1;
	}
	return NULL;
}

static void test_producer_consumer_pipeline(void)
{
	page_pool_thread_init(PIPELINE_PRODUCER_TID);
	memset((void *)pipeline, 0, sizeof(pipeline));
	pipeline_producer_done = 0;

	pthread_t consumers[PIPELINE_CONSUMERS];
	for (int i = 0; i < PIPELINE_CONSUMERS; i++)
		pthread_create(&consumers[i], NULL, pipeline_consumer, (void *)(long)i);

	/* Producer: allocate batches as fast as possible */
	for (int batch = 0; batch < PIPELINE_BATCHES; batch++) {
		void *base = page_pool_get_pages(PIPELINE_PRODUCER_TID, PIPELINE_BATCH_PAGES);
		TEST_ASSERT(base != NULL, "pipeline: get_pages non-NULL");

		/* Write to verify memory is valid */
		memset(base, 0xCC, PIPELINE_BATCH_PAGES * PAGE_SIZE);

		for (int i = 0; i < PIPELINE_BATCH_PAGES; i++)
			pipeline[batch].pages[i] = (char *)base + i * PAGE_SIZE;
		pipeline[batch].count = PIPELINE_BATCH_PAGES;
		pipeline[batch].ready = 1;
	}

	pipeline_producer_done = 1;
	for (int i = 0; i < PIPELINE_CONSUMERS; i++)
		pthread_join(consumers[i], NULL);

	/* Verify all batches consumed */
	int all_consumed = 1;
	for (int i = 0; i < PIPELINE_BATCHES; i++) {
		if (!pipeline[i].consumed)
			all_consumed = 0;
	}
	TEST_ASSERT(all_consumed, "pipeline: all batches consumed");
}

/*
 * Test rapid chunk cycling: allocate-then-free full chunks repeatedly.
 * Exercises the alloc_chunk → munmap → realloc path under pressure.
 */
static void test_rapid_chunk_cycling(void)
{
	int tid = 8;
	page_pool_thread_init(tid);

	for (int cycle = 0; cycle < 5; cycle++) {
		/* Allocate a full batch and immediately free it */
		int nr_pages = CLONE_ALLOC_BATCH;
		void *batch = page_pool_get_pages(tid, nr_pages);
		TEST_ASSERT(batch != NULL, "cycling: get_pages");

		/* Verify we can write (memory is mapped) */
		memset(batch, cycle & 0xFF, nr_pages * PAGE_SIZE);

		/* Free all pages */
		for (int i = 0; i < nr_pages; i++)
			page_pool_put((char *)batch + i * PAGE_SIZE);
	}
}

int main(void)
{
	printf("=== Page Pool Tests ===\n");
	RUN_TEST(test_thread_init);
	RUN_TEST(test_get_returns_aligned);
	RUN_TEST(test_get_pages_contiguous);
	RUN_TEST(test_put_refcount);
	RUN_TEST(test_multi_threaded_no_overlap);
	RUN_TEST(test_nr_chunks);
	RUN_TEST(test_producer_consumer_use_after_free);
	RUN_TEST(test_chunk_exhaustion_and_swap);
	RUN_TEST(test_producer_consumer_pipeline);
	RUN_TEST(test_rapid_chunk_cycling);

	TEST_SUMMARY();
}
