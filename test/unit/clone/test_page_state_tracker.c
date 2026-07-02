#include <pthread.h>
#include <string.h>

#include "test_harness.h"
#include "page.h"
#include "clone/page-state-tracker.h"

static void test_init_destroy(void)
{
	int rc = page_state_init();
	TEST_ASSERT_EQ(rc, 0, "init succeeds");
	page_state_destroy();
}

static void test_set_get_basic(void)
{
	page_state_init();

	unsigned long addr = 0x7f0000001000UL;

	/* Initial state should be UNKNOWN */
	enum page_state st = page_state_get(addr);
	TEST_ASSERT_EQ(st, PAGE_STATE_UNKNOWN, "initial state = UNKNOWN");

	/* Set to IN_BUFFER */
	int rc = page_state_set(addr, PAGE_STATE_IN_BUFFER);
	TEST_ASSERT_EQ(rc, 0, "set to IN_BUFFER succeeds");

	st = page_state_get(addr);
	TEST_ASSERT_EQ(st, PAGE_STATE_IN_BUFFER, "get returns IN_BUFFER");

	/* Transition to DRAIN_PENDING */
	rc = page_state_set(addr, PAGE_STATE_DRAIN_PENDING);
	TEST_ASSERT_EQ(rc, 0, "set to DRAIN_PENDING succeeds");

	st = page_state_get(addr);
	TEST_ASSERT_EQ(st, PAGE_STATE_DRAIN_PENDING, "get returns DRAIN_PENDING");

	/* Transition to COPIED (terminal) */
	rc = page_state_set(addr, PAGE_STATE_COPIED);
	TEST_ASSERT_EQ(rc, 0, "set to COPIED succeeds");

	st = page_state_get(addr);
	TEST_ASSERT_EQ(st, PAGE_STATE_COPIED, "get returns COPIED");

	page_state_destroy();
}

static void test_state_name(void)
{
	TEST_ASSERT(strcmp(page_state_name(PAGE_STATE_UNKNOWN), "UNKNOWN") == 0,
		    "name UNKNOWN");
	TEST_ASSERT(strcmp(page_state_name(PAGE_STATE_IN_BUFFER), "IN_BUFFER") == 0,
		    "name IN_BUFFER");
	TEST_ASSERT(strcmp(page_state_name(PAGE_STATE_COPIED), "COPIED") == 0,
		    "name COPIED");
	TEST_ASSERT(strcmp(page_state_name(PAGE_STATE_UNMAPPED), "UNMAPPED") == 0,
		    "name UNMAPPED");
}

static void test_crc_tracking(void)
{
	page_state_init();

	unsigned long addr = 0x7f0000002000UL;
	char page_data[4096];
	memset(page_data, 0xAB, sizeof(page_data));

	/*
	 * First create the entry with page_state_set (creates it in hash table).
	 * Then use set_with_crc on a valid re-buffer transition to store CRC.
	 */
	page_state_set(addr, PAGE_STATE_IN_BUFFER);

	/* Transition to DIRTY (valid from IN_BUFFER) then re-buffer with CRC */
	page_state_set(addr, PAGE_STATE_DIRTY);
	int rc = page_state_set_with_crc(addr, PAGE_STATE_IN_BUFFER, page_data);
	TEST_ASSERT_EQ(rc, 0, "set_with_crc succeeds");

	/* Check CRC matches with same data */
	u32 stored_crc = 0;
	int match = page_state_check_crc(addr, page_data, &stored_crc);
	TEST_ASSERT(match, "CRC matches same data");
	TEST_ASSERT(stored_crc != 0, "stored CRC is non-zero");

	/* Check CRC mismatch with different data */
	memset(page_data, 0xCD, sizeof(page_data));
	match = page_state_check_crc(addr, page_data, &stored_crc);
	TEST_ASSERT(!match, "CRC mismatches different data");

	/* Buffer count should be 1 (incremented on set_with_crc) */
	u32 count = page_state_get_buffer_count(addr);
	TEST_ASSERT_EQ(count, 1, "buffer count = 1");

	page_state_destroy();
}

static void test_mark_range_unmapped(void)
{
	page_state_init();

	unsigned long start = 0x7f0000010000UL;
	int nr_pages = 10;

	/* First set all pages to IN_BUFFER */
	for (int i = 0; i < nr_pages; i++)
		page_state_set(start + (unsigned long)i * PAGE_SIZE, PAGE_STATE_IN_BUFFER);

	/* Mark range as unmapped */
	page_state_mark_range_unmapped(start, (unsigned long)nr_pages * PAGE_SIZE);

	/* Verify all are UNMAPPED */
	for (int i = 0; i < nr_pages; i++) {
		enum page_state st = page_state_get(start + (unsigned long)i * PAGE_SIZE);
		TEST_ASSERT_EQ(st, PAGE_STATE_UNMAPPED, "page marked unmapped");
	}

	page_state_destroy();
}

static void test_verify_all_terminal_pass(void)
{
	page_state_init();

	unsigned long base = 0x7f0000020000UL;

	/* Set pages to terminal states via valid transitions */
	page_state_set(base, PAGE_STATE_IN_BUFFER);
	page_state_set(base, PAGE_STATE_DRAIN_PENDING);
	page_state_set(base, PAGE_STATE_COPIED);

	page_state_set(base + PAGE_SIZE, PAGE_STATE_IN_BUFFER);
	page_state_set(base + PAGE_SIZE, PAGE_STATE_DISCARDED);

	page_state_set(base + 2 * PAGE_SIZE, PAGE_STATE_IN_BUFFER);
	page_state_set(base + 2 * PAGE_SIZE, PAGE_STATE_UNMAPPED);

	int rc = page_state_verify_all_terminal();
	TEST_ASSERT_EQ(rc, 0, "all terminal passes");

	page_state_destroy();
}

static void test_was_pf_served(void)
{
	page_state_init();

	unsigned long addr = 0x7f0000030000UL;

	/* Page that was NOT served via PF */
	page_state_set(addr, PAGE_STATE_IN_BUFFER);
	page_state_set(addr, PAGE_STATE_DRAIN_PENDING);
	page_state_set(addr, PAGE_STATE_COPIED);
	TEST_ASSERT(!page_state_was_pf_served(addr), "drain path not pf_served");

	/* Page that WAS served via PF */
	unsigned long addr2 = addr + PAGE_SIZE;
	page_state_set(addr2, PAGE_STATE_IN_BUFFER);
	page_state_set(addr2, PAGE_STATE_PF_PENDING);
	page_state_set(addr2, PAGE_STATE_COPIED);
	TEST_ASSERT(page_state_was_pf_served(addr2), "pf path is pf_served");

	page_state_destroy();
}

#define PST_NUM_THREADS 4
#define PST_PAGES_PER_THREAD 500

static void *pst_worker(void *arg)
{
	int id = (int)(long)arg;
	unsigned long base = 0x7f0000100000UL + (unsigned long)id * PST_PAGES_PER_THREAD * PAGE_SIZE;

	for (int i = 0; i < PST_PAGES_PER_THREAD; i++) {
		unsigned long addr = base + (unsigned long)i * PAGE_SIZE;
		page_state_set(addr, PAGE_STATE_IN_BUFFER);
		page_state_set(addr, PAGE_STATE_DRAIN_PENDING);
		page_state_set(addr, PAGE_STATE_COPIED);
	}

	return NULL;
}

static void test_multi_threaded(void)
{
	page_state_init();

	pthread_t threads[PST_NUM_THREADS];
	for (int i = 0; i < PST_NUM_THREADS; i++)
		pthread_create(&threads[i], NULL, pst_worker, (void *)(long)i);
	for (int i = 0; i < PST_NUM_THREADS; i++)
		pthread_join(threads[i], NULL);

	/* Verify all reached COPIED */
	int all_copied = 1;
	for (int id = 0; id < PST_NUM_THREADS; id++) {
		unsigned long base = 0x7f0000100000UL + (unsigned long)id * PST_PAGES_PER_THREAD * PAGE_SIZE;
		for (int i = 0; i < PST_PAGES_PER_THREAD; i++) {
			if (page_state_get(base + (unsigned long)i * PAGE_SIZE) != PAGE_STATE_COPIED) {
				all_copied = 0;
				break;
			}
		}
	}
	TEST_ASSERT(all_copied, "all pages reached COPIED state");

	int rc = page_state_verify_all_terminal();
	TEST_ASSERT_EQ(rc, 0, "verify_all_terminal passes after MT");

	page_state_destroy();
}

int main(void)
{
	printf("=== Page State Tracker Tests ===\n");
	RUN_TEST(test_init_destroy);
	RUN_TEST(test_set_get_basic);
	RUN_TEST(test_state_name);
	RUN_TEST(test_crc_tracking);
	RUN_TEST(test_mark_range_unmapped);
	RUN_TEST(test_verify_all_terminal_pass);
	RUN_TEST(test_was_pf_served);
	RUN_TEST(test_multi_threaded);
	TEST_SUMMARY();
}
