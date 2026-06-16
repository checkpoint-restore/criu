#include <pthread.h>
#include <string.h>

#include "test_harness.h"
#include "xmalloc.h"
#include "clone/spmc-queue.h"

struct payload {
	int value;
};

DECLARE_SPMC_NODE(test, struct payload);

static struct test_spmc_node *q_head;
static struct test_spmc_node *q_tail;
static unsigned long q_size;

static void noop_free(struct payload *p)
{
	(void)p;
}

static void test_init_and_empty(void)
{
	int rc = spmc_init(q_head, q_tail, q_size, struct test_spmc_node);
	TEST_ASSERT_EQ(rc, 0, "init succeeds");
	TEST_ASSERT_EQ(spmc_size(q_size), 0, "initial size = 0");
	TEST_ASSERT(!spmc_peek(q_head), "empty queue peek = false");

	struct payload *p = spmc_dequeue(q_head, q_size);
	TEST_ASSERT(p == NULL, "dequeue from empty = NULL");

	spmc_drain(q_head, noop_free);
}

static void test_single_consumer_fifo(void)
{
	spmc_init(q_head, q_tail, q_size, struct test_spmc_node);

	struct payload items[10];
	for (int i = 0; i < 10; i++) {
		items[i].value = i * 5;
		int rc = spmc_enqueue(q_tail, q_size, &items[i], struct test_spmc_node);
		TEST_ASSERT_EQ(rc, 0, "enqueue succeeds");
	}
	TEST_ASSERT_EQ(spmc_size(q_size), 10, "size = 10 after enqueue");
	TEST_ASSERT(spmc_peek(q_head), "non-empty peek = true");

	for (int i = 0; i < 10; i++) {
		struct payload *p = spmc_dequeue(q_head, q_size);
		TEST_ASSERT(p != NULL, "dequeue non-null");
		if (p)
			TEST_ASSERT_EQ(p->value, i * 5, "FIFO order preserved");
	}
	TEST_ASSERT_EQ(spmc_size(q_size), 0, "size = 0 after drain");

	spmc_drain(q_head, noop_free);
}

#define MC_NUM_ITEMS     50000
#define MC_NUM_CONSUMERS 4

static struct payload mc_items[MC_NUM_ITEMS];
static int mc_received[MC_NUM_ITEMS];
static int mc_total_received;

static void *mc_consumer(void *arg)
{
	(void)arg;
	int count = 0;

	while (__atomic_load_n(&mc_total_received, __ATOMIC_RELAXED) < MC_NUM_ITEMS) {
		struct payload *p = spmc_dequeue(q_head, q_size);
		if (p) {
			__atomic_store_n(&mc_received[p->value], 1, __ATOMIC_RELAXED);
			__atomic_fetch_add(&mc_total_received, 1, __ATOMIC_RELAXED);
			count++;
		}
	}
	return (void *)(long)count;
}

static void test_multi_consumer(void)
{
	spmc_init(q_head, q_tail, q_size, struct test_spmc_node);
	memset(mc_received, 0, sizeof(mc_received));
	__atomic_store_n(&mc_total_received, 0, __ATOMIC_RELAXED);

	/* Enqueue all items first (single producer) */
	for (int i = 0; i < MC_NUM_ITEMS; i++) {
		mc_items[i].value = i;
		spmc_enqueue(q_tail, q_size, &mc_items[i], struct test_spmc_node);
	}

	/* Launch consumers */
	pthread_t threads[MC_NUM_CONSUMERS];
	for (int i = 0; i < MC_NUM_CONSUMERS; i++)
		pthread_create(&threads[i], NULL, mc_consumer, NULL);

	for (int i = 0; i < MC_NUM_CONSUMERS; i++)
		pthread_join(threads[i], NULL);

	/* Verify all items received exactly once */
	int missing = 0;
	for (int i = 0; i < MC_NUM_ITEMS; i++) {
		if (!__atomic_load_n(&mc_received[i], __ATOMIC_RELAXED))
			missing++;
	}
	TEST_ASSERT_EQ(missing, 0, "no items lost with multi-consumer");
	TEST_ASSERT_EQ(__atomic_load_n(&mc_total_received, __ATOMIC_RELAXED),
		       MC_NUM_ITEMS, "total received matches total sent");

	spmc_drain(q_head, noop_free);
}

#define MC_CONCURRENT_ITEMS 100000

static struct payload mc_conc_items[MC_CONCURRENT_ITEMS];
static int mc_conc_received[MC_CONCURRENT_ITEMS];
static int mc_conc_total;

static void *conc_producer(void *arg)
{
	(void)arg;
	for (int i = 0; i < MC_CONCURRENT_ITEMS; i++) {
		mc_conc_items[i].value = i;
		while (spmc_enqueue(q_tail, q_size, &mc_conc_items[i],
				    struct test_spmc_node) != 0) {
		}
	}
	return NULL;
}

static void *conc_consumer(void *arg)
{
	(void)arg;
	while (__atomic_load_n(&mc_conc_total, __ATOMIC_RELAXED) < MC_CONCURRENT_ITEMS) {
		struct payload *p = spmc_dequeue(q_head, q_size);
		if (p) {
			__atomic_store_n(&mc_conc_received[p->value], 1, __ATOMIC_RELAXED);
			__atomic_fetch_add(&mc_conc_total, 1, __ATOMIC_RELAXED);
		}
	}
	return NULL;
}

static void test_concurrent_producer_consumers(void)
{
	spmc_init(q_head, q_tail, q_size, struct test_spmc_node);
	memset(mc_conc_received, 0, sizeof(mc_conc_received));
	__atomic_store_n(&mc_conc_total, 0, __ATOMIC_RELAXED);

	pthread_t prod;
	pthread_t consumers[MC_NUM_CONSUMERS];

	pthread_create(&prod, NULL, conc_producer, NULL);
	for (int i = 0; i < MC_NUM_CONSUMERS; i++)
		pthread_create(&consumers[i], NULL, conc_consumer, NULL);

	pthread_join(prod, NULL);
	for (int i = 0; i < MC_NUM_CONSUMERS; i++)
		pthread_join(consumers[i], NULL);

	int missing = 0;
	for (int i = 0; i < MC_CONCURRENT_ITEMS; i++) {
		if (!__atomic_load_n(&mc_conc_received[i], __ATOMIC_RELAXED))
			missing++;
	}
	TEST_ASSERT_EQ(missing, 0, "no items lost with concurrent prod+cons");

	spmc_drain(q_head, noop_free);
}

static void test_drain(void)
{
	spmc_init(q_head, q_tail, q_size, struct test_spmc_node);

	struct payload items[5];
	for (int i = 0; i < 5; i++) {
		items[i].value = i;
		spmc_enqueue(q_tail, q_size, &items[i], struct test_spmc_node);
	}

	spmc_drain(q_head, noop_free);
	TEST_ASSERT(q_head == NULL, "drain sets head to NULL");
}

int main(void)
{
	printf("=== SPMC Queue Tests ===\n");
	RUN_TEST(test_init_and_empty);
	RUN_TEST(test_single_consumer_fifo);
	RUN_TEST(test_multi_consumer);
	RUN_TEST(test_concurrent_producer_consumers);
	RUN_TEST(test_drain);
	TEST_SUMMARY();
}
