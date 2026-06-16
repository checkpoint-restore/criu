#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdatomic.h>

#include "test_harness.h"
#include "xmalloc.h"
#include "page.h"
#include "clone/spsc-queue.h"
#include "clone/mpsc-queue.h"
#include "clone/spmc-queue.h"
#include "clone/atomic-bitmap.h"

/*
 * Stress tests for lock-free CLONE data structures.
 * These run longer and harder than the basic unit tests to expose
 * race conditions, memory ordering bugs, and performance issues.
 */

/* Forward declarations for free functions */
struct mpsc_payload;
struct spmc_payload;
struct spsc_payload;

static void noop_free_mpsc(struct mpsc_payload *p) { (void)p; }
static void noop_free_spmc(struct spmc_payload *p) { (void)p; }
static void noop_free_spsc(struct spsc_payload *p) { (void)p; }

/* ================================================================
 * MPSC Stress: Many producers, consumer reads while producers enqueue.
 * Tests the window between atomic_exchange on tail and store to prev->next.
 * Consumer must never see garbage — only NULL (empty) or valid entry.
 * ================================================================ */

struct mpsc_payload { int producer_id; int seq; };
DECLARE_MPSC_NODE(stress, struct mpsc_payload);

static struct stress_mpsc_node *mpsc_head;
static struct stress_mpsc_node *mpsc_tail;
static unsigned long mpsc_size;

#define MPSC_PRODUCERS 16
#define MPSC_ITEMS_PER_PROD 50000
#define MPSC_TOTAL (MPSC_PRODUCERS * MPSC_ITEMS_PER_PROD)

static struct mpsc_payload mpsc_items[MPSC_TOTAL];
static atomic_int mpsc_producers_done;
static atomic_long mpsc_consumed;

static void *mpsc_stress_producer(void *arg)
{
	int id = (int)(long)arg;
	int base = id * MPSC_ITEMS_PER_PROD;

	for (int i = 0; i < MPSC_ITEMS_PER_PROD; i++) {
		mpsc_items[base + i].producer_id = id;
		mpsc_items[base + i].seq = i;
		while (mpsc_enqueue(mpsc_tail, mpsc_size, &mpsc_items[base + i],
				    struct stress_mpsc_node) != 0) {
		}
	}
	atomic_fetch_add(&mpsc_producers_done, 1);
	return NULL;
}

static void *mpsc_stress_consumer(void *arg)
{
	(void)arg;
	int per_prod_last[MPSC_PRODUCERS];
	memset(per_prod_last, -1, sizeof(per_prod_last));
	int ordering_violations = 0;
	long count = 0;

	while (count < MPSC_TOTAL) {
		struct mpsc_payload *p = mpsc_dequeue(mpsc_head, mpsc_size);
		if (p) {
			int pid = p->producer_id;
			if (p->seq <= per_prod_last[pid])
				ordering_violations++;
			per_prod_last[pid] = p->seq;
			count++;
		} else if (atomic_load(&mpsc_producers_done) == MPSC_PRODUCERS) {
			/* All producers done but queue not empty yet — spin */
			if (!mpsc_peek(mpsc_head))
				break;
		}
	}

	atomic_store(&mpsc_consumed, count);
	TEST_ASSERT_EQ(ordering_violations, 0,
		       "MPSC stress: per-producer ordering preserved under contention");
	return NULL;
}

static void test_mpsc_stress_concurrent(void)
{
	mpsc_init(mpsc_head, mpsc_tail, mpsc_size, struct stress_mpsc_node);
	atomic_store(&mpsc_producers_done, 0);
	atomic_store(&mpsc_consumed, 0);

	pthread_t producers[MPSC_PRODUCERS];
	pthread_t consumer;

	pthread_create(&consumer, NULL, mpsc_stress_consumer, NULL);
	for (int i = 0; i < MPSC_PRODUCERS; i++)
		pthread_create(&producers[i], NULL, mpsc_stress_producer, (void *)(long)i);

	for (int i = 0; i < MPSC_PRODUCERS; i++)
		pthread_join(producers[i], NULL);
	pthread_join(consumer, NULL);

	long consumed = atomic_load(&mpsc_consumed);
	TEST_ASSERT_EQ(consumed, MPSC_TOTAL,
		       "MPSC stress: all items consumed");

	mpsc_drain(mpsc_head, noop_free_mpsc);
}

/* ================================================================
 * SPMC Stress: One producer, many consumers racing with CAS.
 * Verifies no item is consumed twice (duplicate detection).
 * ================================================================ */

struct spmc_payload { int value; };
DECLARE_SPMC_NODE(stress, struct spmc_payload);

static struct stress_spmc_node *spmc_head;
static struct stress_spmc_node *spmc_tail;
static unsigned long spmc_size;

#define SPMC_CONSUMERS 8
#define SPMC_ITEMS 200000

static struct spmc_payload spmc_items[SPMC_ITEMS];
static atomic_int spmc_seen[SPMC_ITEMS];
static atomic_int spmc_duplicates;
static atomic_long spmc_total_consumed;
static atomic_int spmc_producer_done;

static void *spmc_stress_producer(void *arg)
{
	(void)arg;
	for (int i = 0; i < SPMC_ITEMS; i++) {
		spmc_items[i].value = i;
		while (spmc_enqueue(spmc_tail, spmc_size, &spmc_items[i],
				    struct stress_spmc_node) != 0) {
		}
	}
	atomic_store(&spmc_producer_done, 1);
	return NULL;
}

static void *spmc_stress_consumer(void *arg)
{
	(void)arg;
	long my_count = 0;

	while (1) {
		struct spmc_payload *p = spmc_dequeue(spmc_head, spmc_size);
		if (p) {
			int val = p->value;
			int prev = atomic_fetch_add(&spmc_seen[val], 1);
			if (prev > 0)
				atomic_fetch_add(&spmc_duplicates, 1);
			my_count++;
			atomic_fetch_add(&spmc_total_consumed, 1);
		} else {
			if (atomic_load(&spmc_producer_done) &&
			    atomic_load(&spmc_total_consumed) >= SPMC_ITEMS)
				break;
			if (atomic_load(&spmc_producer_done) && !spmc_peek(spmc_head))
				break;
		}
	}
	return NULL;
}

static void test_spmc_stress_no_duplicates(void)
{
	spmc_init(spmc_head, spmc_tail, spmc_size, struct stress_spmc_node);
	memset((void *)spmc_seen, 0, sizeof(spmc_seen));
	atomic_store(&spmc_duplicates, 0);
	atomic_store(&spmc_total_consumed, 0);
	atomic_store(&spmc_producer_done, 0);

	pthread_t producer;
	pthread_t consumers[SPMC_CONSUMERS];

	pthread_create(&producer, NULL, spmc_stress_producer, NULL);
	for (int i = 0; i < SPMC_CONSUMERS; i++)
		pthread_create(&consumers[i], NULL, spmc_stress_consumer, NULL);

	pthread_join(producer, NULL);
	for (int i = 0; i < SPMC_CONSUMERS; i++)
		pthread_join(consumers[i], NULL);

	int dups = atomic_load(&spmc_duplicates);
	long total = atomic_load(&spmc_total_consumed);
	int missing = 0;
	for (int i = 0; i < SPMC_ITEMS; i++) {
		if (atomic_load(&spmc_seen[i]) == 0)
			missing++;
	}

	TEST_ASSERT_EQ(dups, 0, "SPMC stress: no duplicate consumption");
	TEST_ASSERT_EQ(missing, 0, "SPMC stress: no items lost");
	TEST_ASSERT_EQ(total, SPMC_ITEMS, "SPMC stress: total matches");

	spmc_drain(spmc_head, noop_free_spmc);
}

/* ================================================================
 * SPSC Stress: Rapid produce/consume with varying batch sizes.
 * Tests pipeline depth and memory ordering under rapid cycling.
 * ================================================================ */

struct spsc_payload { long value; };
DECLARE_SPSC_NODE(stress, struct spsc_payload);

static struct stress_spsc_node *spsc_head;
static struct stress_spsc_node *spsc_tail;
static unsigned long spsc_size;

#define SPSC_STRESS_COUNT 1000000

static struct spsc_payload spsc_items[SPSC_STRESS_COUNT];
static atomic_long spsc_consumer_sum;
static atomic_int spsc_consumer_done;

static void *spsc_stress_producer(void *arg)
{
	(void)arg;
	for (long i = 0; i < SPSC_STRESS_COUNT; i++) {
		spsc_items[i].value = i;
		while (spsc_enqueue(spsc_tail, spsc_size, &spsc_items[i],
				    struct stress_spsc_node) != 0) {
		}
	}
	return NULL;
}

static void *spsc_stress_consumer(void *arg)
{
	(void)arg;
	long sum = 0;
	long count = 0;
	long last = -1;
	int ordering_ok = 1;

	while (count < SPSC_STRESS_COUNT) {
		struct spsc_payload *p = spsc_dequeue(spsc_head, spsc_size);
		if (p) {
			if (p->value != last + 1)
				ordering_ok = 0;
			last = p->value;
			sum += p->value;
			count++;
		}
	}

	atomic_store(&spsc_consumer_sum, sum);
	atomic_store(&spsc_consumer_done, ordering_ok);
	return NULL;
}

static void test_spsc_stress_1m(void)
{
	spsc_init(spsc_head, spsc_tail, spsc_size, struct stress_spsc_node);
	atomic_store(&spsc_consumer_sum, 0);
	atomic_store(&spsc_consumer_done, 0);

	pthread_t prod, cons;
	pthread_create(&prod, NULL, spsc_stress_producer, NULL);
	pthread_create(&cons, NULL, spsc_stress_consumer, NULL);
	pthread_join(prod, NULL);
	pthread_join(cons, NULL);

	long expected_sum = (long)(SPSC_STRESS_COUNT - 1) * SPSC_STRESS_COUNT / 2;
	long actual_sum = atomic_load(&spsc_consumer_sum);
	int ordered = atomic_load(&spsc_consumer_done);

	TEST_ASSERT_EQ(actual_sum, expected_sum, "SPSC 1M: checksum matches");
	TEST_ASSERT(ordered, "SPSC 1M: strict sequential ordering");
	TEST_ASSERT_EQ(spsc_size(spsc_size), 0, "SPSC 1M: queue empty");

	spsc_drain(spsc_head, noop_free_spsc);
}

/* ================================================================
 * Atomic Bitmap Stress: Many threads doing test_and_set on same bitmap.
 * Each bit should be "won" by exactly one thread.
 * ================================================================ */

#define BITMAP_STRESS_BITS 4096
#define BITMAP_STRESS_THREADS 8

static uint8_t stress_bitmap[BITMAP_ALLOC_SIZE(BITMAP_STRESS_BITS)];
static atomic_long bitmap_wins[BITMAP_STRESS_THREADS];

static void *bitmap_stress_worker(void *arg)
{
	int id = (int)(long)arg;
	long wins = 0;

	/* Each thread tries to claim every bit via test_and_set */
	for (int i = 0; i < BITMAP_STRESS_BITS; i++) {
		bool was_set = atomic_bitmap_test_and_set(stress_bitmap, i);
		if (!was_set)
			wins++;
	}

	atomic_store(&bitmap_wins[id], wins);
	return NULL;
}

static void test_bitmap_stress_claim(void)
{
	memset(stress_bitmap, 0, sizeof(stress_bitmap));
	for (int i = 0; i < BITMAP_STRESS_THREADS; i++)
		atomic_store(&bitmap_wins[i], 0);

	pthread_t threads[BITMAP_STRESS_THREADS];
	for (int i = 0; i < BITMAP_STRESS_THREADS; i++)
		pthread_create(&threads[i], NULL, bitmap_stress_worker, (void *)(long)i);
	for (int i = 0; i < BITMAP_STRESS_THREADS; i++)
		pthread_join(threads[i], NULL);

	/* Total wins must equal total bits — each bit won exactly once */
	long total_wins = 0;
	for (int i = 0; i < BITMAP_STRESS_THREADS; i++)
		total_wins += atomic_load(&bitmap_wins[i]);

	TEST_ASSERT_EQ(total_wins, BITMAP_STRESS_BITS,
		       "bitmap stress: each bit claimed exactly once");

	/* Verify all bits are set */
	int all_set = 1;
	for (int i = 0; i < BITMAP_STRESS_BITS; i++) {
		if (!atomic_bitmap_test(stress_bitmap, i)) {
			all_set = 0;
			break;
		}
	}
	TEST_ASSERT(all_set, "bitmap stress: all bits set after race");
}

/* ================================================================
 * MPSC rapid drain: Producers enqueue, then drain is called.
 * Verifies no memory leaks (all nodes freed).
 * ================================================================ */

#define DRAIN_PRODUCERS 4
#define DRAIN_ITEMS_PER_PROD 100000

static struct mpsc_payload drain_items[DRAIN_PRODUCERS * DRAIN_ITEMS_PER_PROD];

DECLARE_MPSC_NODE(drain, struct mpsc_payload);
static struct drain_mpsc_node *drain_head;
static struct drain_mpsc_node *drain_tail;
static unsigned long drain_size;

static void *drain_producer(void *arg)
{
	int id = (int)(long)arg;
	int base = id * DRAIN_ITEMS_PER_PROD;

	for (int i = 0; i < DRAIN_ITEMS_PER_PROD; i++) {
		drain_items[base + i].producer_id = id;
		drain_items[base + i].seq = i;
		while (mpsc_enqueue(drain_tail, drain_size, &drain_items[base + i],
				    struct drain_mpsc_node) != 0) {
		}
	}
	return NULL;
}

static void test_mpsc_drain_after_flood(void)
{
	mpsc_init(drain_head, drain_tail, drain_size, struct drain_mpsc_node);

	pthread_t producers[DRAIN_PRODUCERS];
	for (int i = 0; i < DRAIN_PRODUCERS; i++)
		pthread_create(&producers[i], NULL, drain_producer, (void *)(long)i);
	for (int i = 0; i < DRAIN_PRODUCERS; i++)
		pthread_join(producers[i], NULL);

	/* Verify size matches */
	long total = DRAIN_PRODUCERS * DRAIN_ITEMS_PER_PROD;
	TEST_ASSERT_EQ(mpsc_size(drain_size), total, "drain: correct size before drain");

	/* Drain should free all nodes without crashing */
	mpsc_drain(drain_head, noop_free_mpsc);
	TEST_ASSERT(drain_head == NULL, "drain: head NULL after drain");
}

int main(void)
{
	printf("=== Stress Tests ===\n");
	RUN_TEST(test_spsc_stress_1m);
	RUN_TEST(test_mpsc_stress_concurrent);
	RUN_TEST(test_spmc_stress_no_duplicates);
	RUN_TEST(test_bitmap_stress_claim);
	RUN_TEST(test_mpsc_drain_after_flood);
	TEST_SUMMARY();
}
