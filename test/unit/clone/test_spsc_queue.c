#include <pthread.h>

#include "test_harness.h"
#include "xmalloc.h"
#include "clone/spsc-queue.h"

struct payload {
	int value;
};

DECLARE_SPSC_NODE(test, struct payload);

static struct test_spsc_node *q_head;
static struct test_spsc_node *q_tail;
static unsigned long q_size;

static void noop_free(struct payload *p)
{
	(void)p;
}

static void test_init_and_empty(void)
{
	int rc = spsc_init(q_head, q_tail, q_size, struct test_spsc_node);
	TEST_ASSERT_EQ(rc, 0, "init succeeds");
	TEST_ASSERT_EQ(spsc_size(q_size), 0, "initial size = 0");
	TEST_ASSERT(!spsc_peek(q_head), "empty queue peek = false");

	struct payload *p = spsc_dequeue(q_head, q_size);
	TEST_ASSERT(p == NULL, "dequeue from empty = NULL");

	spsc_drain(q_head, noop_free);
}

static void test_enqueue_dequeue_fifo(void)
{
	spsc_init(q_head, q_tail, q_size, struct test_spsc_node);

	struct payload items[5];
	for (int i = 0; i < 5; i++) {
		items[i].value = i * 10;
		int rc = spsc_enqueue(q_tail, q_size, &items[i], struct test_spsc_node);
		TEST_ASSERT_EQ(rc, 0, "enqueue succeeds");
	}
	TEST_ASSERT_EQ(spsc_size(q_size), 5, "size = 5 after enqueue");
	TEST_ASSERT(spsc_peek(q_head), "non-empty peek = true");

	for (int i = 0; i < 5; i++) {
		struct payload *p = spsc_dequeue(q_head, q_size);
		TEST_ASSERT(p != NULL, "dequeue non-null");
		if (p)
			TEST_ASSERT_EQ(p->value, i * 10, "FIFO order preserved");
	}
	TEST_ASSERT_EQ(spsc_size(q_size), 0, "size = 0 after drain");
	TEST_ASSERT(!spsc_peek(q_head), "empty after drain");

	spsc_drain(q_head, noop_free);
}

#define STRESS_COUNT 100000

static struct payload stress_items[STRESS_COUNT];
static int consumer_results[STRESS_COUNT];
static int consumer_count;

static void *producer_thread(void *arg)
{
	(void)arg;
	for (int i = 0; i < STRESS_COUNT; i++) {
		stress_items[i].value = i;
		while (spsc_enqueue(q_tail, q_size, &stress_items[i],
				    struct test_spsc_node) != 0) {
		}
	}
	return NULL;
}

static void *consumer_thread(void *arg)
{
	(void)arg;
	consumer_count = 0;
	while (consumer_count < STRESS_COUNT) {
		struct payload *p = spsc_dequeue(q_head, q_size);
		if (p)
			consumer_results[consumer_count++] = p->value;
	}
	return NULL;
}

static void test_threaded_stress(void)
{
	spsc_init(q_head, q_tail, q_size, struct test_spsc_node);

	pthread_t prod, cons;
	pthread_create(&prod, NULL, producer_thread, NULL);
	pthread_create(&cons, NULL, consumer_thread, NULL);
	pthread_join(prod, NULL);
	pthread_join(cons, NULL);

	int ordered = 1;
	for (int i = 0; i < STRESS_COUNT; i++) {
		if (consumer_results[i] != i) {
			ordered = 0;
			break;
		}
	}
	TEST_ASSERT(ordered, "threaded: FIFO ordering preserved across 100K items");
	TEST_ASSERT_EQ(spsc_size(q_size), 0, "threaded: queue empty at end");

	spsc_drain(q_head, noop_free);
}

static void test_drain(void)
{
	spsc_init(q_head, q_tail, q_size, struct test_spsc_node);

	struct payload items[3];
	for (int i = 0; i < 3; i++) {
		items[i].value = i;
		spsc_enqueue(q_tail, q_size, &items[i], struct test_spsc_node);
	}

	TEST_ASSERT_EQ(spsc_size(q_size), 3, "3 items before drain");
	spsc_drain(q_head, noop_free);
	TEST_ASSERT(q_head == NULL, "drain sets head to NULL");
}

int main(void)
{
	printf("=== SPSC Queue Tests ===\n");
	RUN_TEST(test_init_and_empty);
	RUN_TEST(test_enqueue_dequeue_fifo);
	RUN_TEST(test_threaded_stress);
	RUN_TEST(test_drain);
	TEST_SUMMARY();
}
