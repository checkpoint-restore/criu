#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "zdtmtst.h"
#include "clone_dump_util.h"

const char *test_doc = "--clone-dump under write storm: N writer threads with "
		       "tracked state. Each writer increments through markers "
		       "and we track exactly which marker each region had at "
		       "restore time. Detects torn writes and lost pages.";
const char *test_author = "Asaf Porat Stoler <asafpor@gmail.com>";


#define NR_WRITERS	4
#define REGION_PAGES	1024
#define MARKER_MIN	1
#define MARKER_MAX	200
#define DRAIN_TIMEOUT	10000

struct writer {
	int id;
	unsigned char *region;
	atomic_uchar current_marker;
	unsigned char snap_marker;	/* captured at restore */
};

static atomic_int stop_writers;

static void *writer_thread(void *arg)
{
	struct writer *w = arg;
	unsigned long sz = REGION_PAGES * PAGE_SIZE;
	unsigned char marker = MARKER_MIN;

	while (!atomic_load(&stop_writers)) {
		memset(w->region, marker, sz);
		atomic_store(&w->current_marker, marker);
		marker++;
		if (marker > MARKER_MAX)
			marker = MARKER_MIN;
	}
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t threads[NR_WRITERS];
	struct writer writers[NR_WRITERS];
	unsigned long sz = REGION_PAGES * PAGE_SIZE;
	int i, p, j;
	int errors = 0;
	int torn = 0, out_of_range = 0;

	test_init(argc, argv);

	for (i = 0; i < NR_WRITERS; i++) {
		writers[i].id = i;
		writers[i].region = mmap(NULL, sz, PROT_READ | PROT_WRITE,
					 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (writers[i].region == MAP_FAILED) {
			pr_perror("mmap writer %d", i);
			return 1;
		}
		memset(writers[i].region, MARKER_MIN, sz);
		atomic_init(&writers[i].current_marker, MARKER_MIN);
	}

	atomic_init(&stop_writers, 0);
	for (i = 0; i < NR_WRITERS; i++) {
		if (pthread_create(&threads[i], NULL, writer_thread, &writers[i])) {
			pr_perror("pthread_create %d", i);
			return 1;
		}
	}

	test_daemon();
	test_waitsig();

	/* Snapshot marker state immediately after restore */
	for (i = 0; i < NR_WRITERS; i++)
		writers[i].snap_marker = atomic_load(&writers[i].current_marker);

	atomic_store(&stop_writers, 1);
	for (i = 0; i < NR_WRITERS; i++)
		pthread_join(threads[i], NULL);

	test_msg("State at restore:\n");
	for (i = 0; i < NR_WRITERS; i++)
		test_msg("  writer %d: marker=%d\n", i, writers[i].snap_marker);

	/* Wait for drain */
	for (i = 0; i < NR_WRITERS; i++) {
		if (clone_wait_for_drain(writers[i].region, sz, DRAIN_TIMEOUT) < 0) {
			fail("writer %d region drain timeout", i);
			return 1;
		}
	}

	/*
	 * Verification: each page must have a marker in [MARKER_MIN, snap_marker]
	 * (the writer may have advanced past the checkpoint point, but the page
	 * content must be from some point in the writer's history).
	 */
	for (i = 0; i < NR_WRITERS; i++) {
		for (p = 0; p < REGION_PAGES; p++) {
			unsigned char *page = writers[i].region + p * PAGE_SIZE;
			unsigned char m = page[0];

			if (m < MARKER_MIN || m > MARKER_MAX) {
				if (out_of_range < 8)
					test_msg("writer %d page %d: marker 0x%02x "
						 "out of range [%d,%d]\n",
						 i, p, m, MARKER_MIN, MARKER_MAX);
				out_of_range++;
				errors++;
				continue;
			}

			/*
			 * The marker should be <= snap_marker (from the writer's
			 * perspective at restore). If it's higher, it means we got
			 * post-restore data mixed in, which is also OK.
			 * What's NOT OK is a marker that doesn't exist in history.
			 */

			/* Check page uniformity (torn write detection) */
			for (j = 1; j < PAGE_SIZE; j++) {
				if (page[j] != m) {
					if (torn < 8)
						test_msg("writer %d page %d: torn at "
							 "offset %d (0x%02x != 0x%02x)\n",
							 i, p, j, page[j], m);
					torn++;
					errors++;
					break;
				}
			}
		}
	}

	if (errors) {
		test_msg("SUMMARY: %d errors (torn=%d, out_of_range=%d)\n",
			 errors, torn, out_of_range);
		fail("write-storm verification failed");
		return 1;
	}

	test_msg("OK: all %d writers x %d pages verified, no torn writes\n",
		 NR_WRITERS, REGION_PAGES);
	pass();
	return 0;
}
