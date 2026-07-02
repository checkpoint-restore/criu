#include <pthread.h>
#include <string.h>

#include "test_harness.h"
#include "xmalloc.h"
#include "clone/mpsc-queue.h"

struct payload {
	int value;
	int producer_id;
};

DECLARE_MPSC_NODE(test, struct payload);

static struct test_mpsc_node *q_head;
static struct test_mpsc_node *q_tail;
static unsigned long q_size;

static void noop_free(struct payload *p)
{
	(void)p;
}

static void test_init_and_empty(void)
{
	int rc = mpsc_init(q_head, q_tail, q_size, struct test_mpsc_node);
	TEST_ASSERT_EQ(rc, 0, "init succeeds");
	TEST_ASSERT_EQ(mpsc_size(q_size), 0, "initial size = 0");
	TEST_ASSERT(!mpsc_peek(q_head), "empty queue peek = false");

	struct payload *p = mpsc_dequeue(q_head, q_size);
	TEST_ASSERT(p == NULL, "dequeue from empty = NULL");

	mpsc_drain(q_head, noop_free);
}

static void test_single_producer_fifo(void)
{
	mpsc_init(q_head, q_tail, q_size, struct test_mpsc_node);

	struct payload items[10];
	for (int i = 0; i < 10; i++) {
		items[i].value = i;
		items[i].producer_id = 0;
		int rc = mpsc_enqueue(q_tail, q_size, &items[i], struct test_mpsc_node);
		TEST_ASSERT_EQ(rc, 0, "enqueue succeeds");
	}
	TEST_ASSERT_EQ(mpsc_size(q_size), 10, "size = 10");

	for (int i = 0; i < 10; i++) {
		struct payload *p = mpsc_dequeue(q_head, q_size);
		TEST_ASSERT(p != NULL, "dequeue non-null");
		if (p)
			TEST_ASSERT_EQ(p->value, i, "FIFO order");
	}
	TEST_ASSERT_EQ(mpsc_size(q_size), 0, "empty after drain");

	mpsc_drain(q_head, noop_free);
}

#define NUM_PRODUCERS    8
#define ITEMS_PER_PROD   10000
#define TOTAL_ITEMS      (NUM_PRODUCERS * ITEMS_PER_PROD)

static struct payload all_items[TOTAL_ITEMS];

static void *mpsc_producer(void *arg)
{
	int id = (int)(long)arg;
	for (int i = 0; i < ITEMS_PER_PROD; i++) {
		int idx = id * ITEMS_PER_PROD + i;
		all_items[idx].value = i;
		all_items[idx].producer_id = id;
		while (mpsc_enqueue(q_tail, q_size, &all_items[idx],
				    struct test_mpsc_node) != 0) {
		}
	}
	return NULL;
}

static void test_multi_producer(void)
{
	mpsc_init(q_head, q_tail, q_size, struct test_mpsc_node);

	pthread_t threads[NUM_PRODUCERS];
	for (int i = 0; i < NUM_PRODUCERS; i++)
		pthread_create(&threads[i], NULL, mpsc_producer, (void *)(long)i);
	for (int i = 0; i < NUM_PRODUCERS; i++)
		pthread_join(threads[i], NULL);

	/* Consume all and verify per-producer ordering */
	int per_prod_last[NUM_PRODUCERS];
	memset(per_prod_last, -1, sizeof(per_prod_last));
	int total = 0;
	int ordering_ok = 1;

	struct payload *p;
	while ((p = mpsc_dequeue(q_head, q_size)) != NULL) {
		int pid = p->producer_id;
		if (p->value <= per_prod_last[pid])
			ordering_ok = 0;
		per_prod_last[pid] = p->value;
		total++;
	}

	TEST_ASSERT_EQ(total, TOTAL_ITEMS, "all items received");
	TEST_ASSERT(ordering_ok, "per-producer FIFO ordering preserved");
	TEST_ASSERT_EQ(mpsc_size(q_size), 0, "queue empty at end");

	mpsc_drain(q_head, noop_free);
}

static void test_size_accuracy(void)
{
	mpsc_init(q_head, q_tail, q_size, struct test_mpsc_node);

	struct payload items[100];
	for (int i = 0; i < 100; i++) {
		items[i].value = i;
		mpsc_enqueue(q_tail, q_size, &items[i], struct test_mpsc_node);
	}
	TEST_ASSERT_EQ(mpsc_size(q_size), 100, "size after 100 enqueues");

	for (int i = 0; i < 50; i++)
		mpsc_dequeue(q_head, q_size);
	TEST_ASSERT_EQ(mpsc_size(q_size), 50, "size after 50 dequeues");

	for (int i = 0; i < 50; i++)
		mpsc_dequeue(q_head, q_size);
	TEST_ASSERT_EQ(mpsc_size(q_size), 0, "size after full drain");

	mpsc_drain(q_head, noop_free);
}

static void test_drain(void)
{
	mpsc_init(q_head, q_tail, q_size, struct test_mpsc_node);

	struct payload items[5];
	for (int i = 0; i < 5; i++) {
		items[i].value = i;
		mpsc_enqueue(q_tail, q_size, &items[i], struct test_mpsc_node);
	}

	mpsc_drain(q_head, noop_free);
	TEST_ASSERT(q_head == NULL, "drain sets head to NULL");
}

int main(void)
{
	printf("=== MPSC Queue Tests ===\n");
	RUN_TEST(test_init_and_empty);
	RUN_TEST(test_single_producer_fifo);
	RUN_TEST(test_multi_producer);
	RUN_TEST(test_size_accuracy);
	RUN_TEST(test_drain);
	TEST_SUMMARY();
}
