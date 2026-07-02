#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "test_harness.h"
#include "page.h"
#include "clone/hung-page-tracker.h"

static void test_init_destroy(void)
{
	int rc = pf_tracker_init();
	TEST_ASSERT_EQ(rc, 0, "init succeeds");

	/* Double init is safe */
	rc = pf_tracker_init();
	TEST_ASSERT_EQ(rc, 0, "double init returns 0");

	pf_tracker_destroy();
}

static void test_add_and_complete(void)
{
	pf_tracker_init();

	unsigned long long addr = 0x7f0000001000ULL;

	/* Add a page fault entry */
	pf_tracker_add(addr, 1, 1234, true);

	/* Transition to completed */
	pf_tracker_set_state(addr, PF_STATE_COMPLETED);

	/* print_stats should clean it up without crashing */
	pf_tracker_print_stats();

	pf_tracker_destroy();
}

static void test_set_state_unknown_address(void)
{
	pf_tracker_init();

	/* Setting state on unknown address should not crash */
	pf_tracker_set_state(0xDEAD0000ULL, PF_STATE_COMPLETED);
	pf_tracker_set_state(0xBEEF0000ULL, PF_STATE_PENDING_EAGAIN);

	pf_tracker_destroy();
}

static void test_state_transitions(void)
{
	pf_tracker_init();

	unsigned long long addr = 0x7f0000002000ULL;

	/* PENDING_SERVER (default on add) → PENDING_EAGAIN → COMPLETED */
	pf_tracker_add(addr, 4, 5678, true);

	pf_tracker_set_state(addr, PF_STATE_PENDING_EAGAIN);
	pf_tracker_set_state(addr, PF_STATE_COMPLETED);

	/* After COMPLETED, print_stats should clean it */
	pf_tracker_print_stats();

	pf_tracker_destroy();
}

static void test_multiple_entries_same_bucket(void)
{
	pf_tracker_init();

	/*
	 * Hash = (addr >> 12) & 0xFFF
	 * Two addresses with same hash:
	 * 0x7f0000001000 >> 12 = 0x7f0000001, & 0xFFF = 0x001
	 * 0x7f0001001000 >> 12 = 0x7f0001001, & 0xFFF = 0x001
	 */
	unsigned long long addr1 = 0x7f0000001000ULL;
	unsigned long long addr2 = 0x7f0001001000ULL;

	pf_tracker_add(addr1, 1, 100, true);
	pf_tracker_add(addr2, 1, 200, false);

	/* Complete addr1, addr2 stays pending */
	pf_tracker_set_state(addr1, PF_STATE_COMPLETED);

	/* print_stats should report addr2 as pending */
	pf_tracker_print_stats();

	/* Now complete addr2 */
	pf_tracker_set_state(addr2, PF_STATE_COMPLETED);
	pf_tracker_print_stats();

	pf_tracker_destroy();
}

static void test_background_vs_pf(void)
{
	pf_tracker_init();

	/* Add both PF and background entries */
	pf_tracker_add(0x1000ULL, 1, 100, true);   /* page fault */
	pf_tracker_add(0x2000ULL, 16, 100, false);  /* background transfer */

	pf_tracker_set_state(0x1000ULL, PF_STATE_COMPLETED);
	pf_tracker_set_state(0x2000ULL, PF_STATE_COMPLETED);
	pf_tracker_print_stats();

	pf_tracker_destroy();
}

static void test_operations_before_init(void)
{
	/* These should not crash when tracker is not initialized */
	pf_tracker_add(0x1000ULL, 1, 1, true);
	pf_tracker_set_state(0x1000ULL, PF_STATE_COMPLETED);
	pf_tracker_print_stats();
	pf_tracker_destroy();
}

#define HPT_NUM_THREADS 4
#define HPT_ENTRIES_PER_THREAD 500

static void *hpt_worker(void *arg)
{
	int id = (int)(long)arg;
	unsigned long long base = (unsigned long long)id * HPT_ENTRIES_PER_THREAD * PAGE_SIZE;

	for (int i = 0; i < HPT_ENTRIES_PER_THREAD; i++) {
		unsigned long long addr = base + (unsigned long long)i * PAGE_SIZE;
		pf_tracker_add(addr, 1, id, true);
	}

	/* Complete them all */
	for (int i = 0; i < HPT_ENTRIES_PER_THREAD; i++) {
		unsigned long long addr = base + (unsigned long long)i * PAGE_SIZE;
		pf_tracker_set_state(addr, PF_STATE_COMPLETED);
	}

	return NULL;
}

static void test_multi_threaded(void)
{
	pf_tracker_init();

	pthread_t threads[HPT_NUM_THREADS];
	for (int i = 0; i < HPT_NUM_THREADS; i++)
		pthread_create(&threads[i], NULL, hpt_worker, (void *)(long)i);
	for (int i = 0; i < HPT_NUM_THREADS; i++)
		pthread_join(threads[i], NULL);

	/* All entries should be COMPLETED, print_stats cleans them */
	pf_tracker_print_stats();

	pf_tracker_destroy();
}

int main(void)
{
	printf("=== Hung Page Tracker Tests ===\n");
	RUN_TEST(test_init_destroy);
	RUN_TEST(test_add_and_complete);
	RUN_TEST(test_set_state_unknown_address);
	RUN_TEST(test_state_transitions);
	RUN_TEST(test_multiple_entries_same_bucket);
	RUN_TEST(test_background_vs_pf);
	RUN_TEST(test_operations_before_init);
	RUN_TEST(test_multi_threaded);
	TEST_SUMMARY();
}
