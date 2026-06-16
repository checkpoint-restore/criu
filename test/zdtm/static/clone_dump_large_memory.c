#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "zdtmtst.h"
#include "clone_dump_util.h"

const char *test_doc = "--clone-dump scale test: large anon-private region with "
		       "random writer. Tracks exactly which pages were modified "
		       "to detect both corruption and lost updates.";
const char *test_author = "Asaf Porat Stoler <asafpor@gmail.com>";


#ifndef CLONE_LARGE_MEMORY_MB
#define CLONE_LARGE_MEMORY_MB	256
#endif
#define TOTAL_MB		CLONE_LARGE_MEMORY_MB
#define NR_PAGES	((TOTAL_MB * 1024UL * 1024UL) / 4096UL)
#define MARKER_INIT	0x11
#define MARKER_WRITER	0xAA

static atomic_int stop_writer;
static atomic_size_t pages_written;
static unsigned char *mem;

/* Bitmap to track which pages were written */
static unsigned char *written_bitmap;

static inline void bitmap_set(size_t idx)
{
	written_bitmap[idx / 8] |= (1 << (idx % 8));
}

static inline int bitmap_test(size_t idx)
{
	return (written_bitmap[idx / 8] >> (idx % 8)) & 1;
}

static void *writer_thread(void *arg)
{
	unsigned long n = NR_PAGES;
	unsigned int seed = 0xDEADBEEF;

	while (!atomic_load(&stop_writer)) {
		unsigned long idx = rand_r(&seed) % n;
		memset(mem + idx * PAGE_SIZE, MARKER_WRITER, PAGE_SIZE);
		bitmap_set(idx);
		atomic_fetch_add(&pages_written, 1);
	}
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t th;
	unsigned long sz = NR_PAGES * PAGE_SIZE;
	unsigned long i;
	int j;
	int errors = 0;
	int init_errors = 0, writer_errors = 0, torn = 0;
	size_t snap_pages_written;
	size_t expected_init = 0, expected_written = 0;

	test_init(argc, argv);

	mem = mmap(NULL, sz, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED) {
		pr_perror("mmap %lu bytes", sz);
		return 1;
	}

	/* Bitmap for tracking which pages were written */
	written_bitmap = calloc((NR_PAGES + 7) / 8, 1);
	if (!written_bitmap) {
		pr_perror("calloc bitmap");
		return 1;
	}

	memset(mem, MARKER_INIT, sz);

	atomic_init(&stop_writer, 0);
	atomic_init(&pages_written, 0);

	if (pthread_create(&th, NULL, writer_thread, NULL)) {
		pr_perror("pthread_create");
		return 1;
	}

	test_daemon();
	test_waitsig();

	snap_pages_written = atomic_load(&pages_written);

	atomic_store(&stop_writer, 1);
	pthread_join(th, NULL);

	test_msg("State at restore: pages_written=%zu (may include duplicates)\n",
		 snap_pages_written);

	{
		unsigned long drain_ms = 10000UL * (TOTAL_MB / 1024UL + 1);
		if (clone_wait_for_drain(mem, sz, (unsigned int)drain_ms) < 0) {
			fail("drain did not complete within %lu ms", drain_ms);
			return 1;
		}
	}

	/*
	 * Verify each page. Expected state based on bitmap:
	 * - If bitmap_test(i): page should have MARKER_WRITER
	 * - Otherwise: page should have MARKER_INIT
	 */
	for (i = 0; i < NR_PAGES; i++) {
		unsigned char *page = mem + i * PAGE_SIZE;
		unsigned char m = page[0];
		unsigned char expected;
		int was_written = bitmap_test(i);

		if (was_written) {
			expected = MARKER_WRITER;
			expected_written++;
		} else {
			expected = MARKER_INIT;
			expected_init++;
		}

		if (m != expected) {
			if (errors < 16) {
				test_msg("page %lu: got 0x%02x expected 0x%02x "
					 "(was_written=%d)\n",
					 i, m, expected, was_written);
			}
			if (was_written)
				writer_errors++;
			else
				init_errors++;
			errors++;
			continue;
		}

		/* Check for torn writes */
		for (j = 1; j < PAGE_SIZE; j++) {
			if (page[j] != m) {
				if (torn < 8)
					test_msg("page %lu: torn at offset %d "
						 "(0x%02x != 0x%02x)\n",
						 i, j, page[j], m);
				torn++;
				errors++;
				break;
			}
		}
	}

	if (errors) {
		test_msg("SUMMARY: %d errors (init_wrong=%d, writer_wrong=%d, torn=%d)\n",
			 errors, init_errors, writer_errors, torn);
		test_msg("Expected: %zu init pages, %zu written pages\n",
			 expected_init, expected_written);
		fail("large memory verification failed");
		return 1;
	}

	test_msg("OK: %lu pages verified (%zu init, %zu written), no errors\n",
		 (unsigned long)NR_PAGES, expected_init, expected_written);
	pass();
	return 0;
}
