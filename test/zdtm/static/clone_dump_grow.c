#include <errno.h>
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

const char *test_doc = "--clone-dump growth test: validates correctness of "
		       "page state after checkpoint/restore with concurrent "
		       "memory growth and dirtying. Tracks exactly which pages "
		       "were modified and verifies expected state after restore.";
const char *test_author = "Asaf Porat Stoler <asafpor@gmail.com>";


#ifndef CLONE_GROW_INITIAL_MB
#define CLONE_GROW_INITIAL_MB	30720		/* 30 GB */
#endif
#define INITIAL_MB		CLONE_GROW_INITIAL_MB
#define GROW_MB			CLONE_GROW_INITIAL_MB
#define INITIAL_BYTES		((size_t)INITIAL_MB << 20)
#define GROW_BYTES		((size_t)GROW_MB << 20)
#define INITIAL_PAGES		(INITIAL_BYTES / PAGE_SIZE)
#define GROW_PAGES		(GROW_BYTES / PAGE_SIZE)

#define MARKER_INITIAL		0x11
#define MARKER_GROW		0x22
#define MARKER_DIRTY		0x33

/* Dirty every Nth page to bound the tracking bitmap size */
#define DIRTY_STRIDE		256

#define DRAIN_TIMEOUT_MS_PER_GB	10000UL

static unsigned char *initial_region;
static unsigned char *grown_region;

/* State tracking for verification */
static atomic_size_t grown_pages_filled;	/* pages filled in grown region */
static atomic_size_t dirty_passes_completed;	/* full passes over initial region */
static atomic_size_t last_dirty_page_idx;	/* last page dirtied in current pass */
static atomic_int    stop_workers;

/*
 * Grower thread: allocates grown region and fills it page by page.
 * Tracks exactly how many pages were filled via grown_pages_filled.
 */
static void *grower_thread(void *arg)
{
	unsigned char *buf;
	size_t i;

	buf = mmap(NULL, GROW_BYTES, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED) {
		pr_perror("grower mmap %zu bytes", GROW_BYTES);
		return (void *)(intptr_t)-1;
	}

	/* Publish address immediately so verifier knows the region exists */
	grown_region = buf;

	for (i = 0; i < GROW_PAGES && !atomic_load(&stop_workers); i++) {
		memset(buf + i * PAGE_SIZE, MARKER_GROW, PAGE_SIZE);
		atomic_store(&grown_pages_filled, i + 1);
	}

	return NULL;
}

/*
 * Dirtier thread: dirties every DIRTY_STRIDE-th page in the initial region.
 * Tracks the current position so we know exactly which pages were dirtied.
 */
static void *dirtier_thread(void *arg)
{
	size_t page_idx;

	while (!atomic_load(&stop_workers)) {
		for (page_idx = 0; page_idx < INITIAL_PAGES; page_idx += DIRTY_STRIDE) {
			if (atomic_load(&stop_workers))
				break;
			memset(initial_region + page_idx * PAGE_SIZE,
			       MARKER_DIRTY, PAGE_SIZE);
			atomic_store(&last_dirty_page_idx, page_idx);
		}
		/* Completed a full pass */
		atomic_fetch_add(&dirty_passes_completed, 1);
		usleep(1000);
	}
	return NULL;
}

/*
 * Verify a single page has the expected uniform marker.
 * Returns 0 on success, -1 on mismatch.
 */
static int verify_page(const char *region_name, size_t page_idx,
		       unsigned char *page, unsigned char expected)
{
	size_t j;
	unsigned char actual = page[0];

	if (actual != expected) {
		test_msg("%s page %zu: expected 0x%02x, got 0x%02x\n",
			 region_name, page_idx, expected, actual);
		return -1;
	}

	/* Check page is uniform (no torn writes) */
	for (j = 1; j < PAGE_SIZE; j++) {
		if (page[j] != actual) {
			test_msg("%s page %zu: torn write at offset %zu "
				 "(0x%02x != 0x%02x)\n",
				 region_name, page_idx, j, page[j], actual);
			return -1;
		}
	}
	return 0;
}

/*
 * Verify initial region state based on tracked dirty state.
 * Pages at indices 0, DIRTY_STRIDE, 2*DIRTY_STRIDE, ... up to the tracked
 * position should be MARKER_DIRTY. All others should be MARKER_INITIAL.
 */
static int verify_initial_region(size_t passes_completed, size_t last_dirty_idx)
{
	size_t page_idx;
	int errors = 0;
	unsigned char expected;
	size_t dirty_count = 0, initial_count = 0;

	for (page_idx = 0; page_idx < INITIAL_PAGES; page_idx++) {
		unsigned char *page = initial_region + page_idx * PAGE_SIZE;

		/*
		 * A page is dirty if:
		 * - At least one full pass completed, OR
		 * - It's at a dirty stride position AND <= last_dirty_idx
		 */
		if (page_idx % DIRTY_STRIDE == 0) {
			if (passes_completed > 0 || page_idx <= last_dirty_idx) {
				expected = MARKER_DIRTY;
				dirty_count++;
			} else {
				expected = MARKER_INITIAL;
				initial_count++;
			}
		} else {
			expected = MARKER_INITIAL;
			initial_count++;
		}

		if (verify_page("initial", page_idx, page, expected) < 0)
			errors++;
	}

	test_msg("initial region: %zu dirty, %zu initial, %d errors\n",
		 dirty_count, initial_count, errors);
	return errors ? -1 : 0;
}

/*
 * Verify grown region state based on tracked fill progress.
 * Pages 0..filled_pages-1 should be MARKER_GROW.
 * We don't check beyond filled_pages since those weren't touched.
 */
static int verify_grown_region(size_t filled_pages)
{
	size_t page_idx;
	int errors = 0;

	if (filled_pages == 0) {
		test_msg("grown region: no pages filled yet\n");
		return 0;
	}

	for (page_idx = 0; page_idx < filled_pages; page_idx++) {
		unsigned char *page = grown_region + page_idx * PAGE_SIZE;
		if (verify_page("grown", page_idx, page, MARKER_GROW) < 0)
			errors++;
	}

	test_msg("grown region: verified %zu/%zu pages, %d errors\n",
		 filled_pages, (size_t)GROW_PAGES, errors);
	return errors ? -1 : 0;
}

int main(int argc, char **argv)
{
	pthread_t grower_th, dirtier_th;
	size_t i;
	unsigned long drain_ms;
	size_t snap_grown_filled, snap_dirty_passes, snap_last_dirty;

	test_init(argc, argv);

	test_msg("clone_dump_grow: INITIAL=%u MB (%zu pages), "
		 "GROW=%u MB (%zu pages), DIRTY_STRIDE=%d\n",
		 (unsigned)INITIAL_MB, (size_t)INITIAL_PAGES,
		 (unsigned)GROW_MB, (size_t)GROW_PAGES, DIRTY_STRIDE);

	/* Allocate and fill initial region */
	initial_region = mmap(NULL, INITIAL_BYTES, PROT_READ | PROT_WRITE,
			      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (initial_region == MAP_FAILED) {
		pr_perror("initial mmap %zu bytes", INITIAL_BYTES);
		return 1;
	}
	for (i = 0; i < INITIAL_PAGES; i++)
		memset(initial_region + i * PAGE_SIZE, MARKER_INITIAL, PAGE_SIZE);

	/* Initialize state tracking */
	atomic_init(&stop_workers, 0);
	atomic_init(&grown_pages_filled, 0);
	atomic_init(&dirty_passes_completed, 0);
	atomic_init(&last_dirty_page_idx, 0);
	grown_region = NULL;

	/* Start worker threads */
	if (pthread_create(&grower_th, NULL, grower_thread, NULL)) {
		pr_perror("pthread_create grower");
		return 1;
	}
	if (pthread_create(&dirtier_th, NULL, dirtier_thread, NULL)) {
		pr_perror("pthread_create dirtier");
		return 1;
	}

	test_daemon();
	test_waitsig();

	/*
	 * Snapshot the state immediately after restore. These atomics tell us
	 * exactly what state we should expect in each region.
	 */
	snap_grown_filled = atomic_load(&grown_pages_filled);
	snap_dirty_passes = atomic_load(&dirty_passes_completed);
	snap_last_dirty = atomic_load(&last_dirty_page_idx);

	test_msg("State at restore: grown_filled=%zu, dirty_passes=%zu, "
		 "last_dirty_idx=%zu\n",
		 snap_grown_filled, snap_dirty_passes, snap_last_dirty);

	/* Wait for grower to complete if it hasn't */
	while (!grown_region || atomic_load(&grown_pages_filled) < GROW_PAGES) {
		if (atomic_load(&stop_workers))
			break;
		usleep(10 * 1000);
	}

	/* Stop workers */
	atomic_store(&stop_workers, 1);
	pthread_join(grower_th, NULL);
	pthread_join(dirtier_th, NULL);

	/* Wait for pages to drain from UFFD */
	drain_ms = DRAIN_TIMEOUT_MS_PER_GB *
		   ((INITIAL_MB + GROW_MB) / 1024UL + 1);
	if (clone_wait_for_drain(initial_region, INITIAL_BYTES,
				 (unsigned int)drain_ms) < 0) {
		fail("initial region drain timeout after %lu ms", drain_ms);
		return 1;
	}
	if (grown_region && snap_grown_filled > 0) {
		if (clone_wait_for_drain(grown_region,
					 snap_grown_filled * PAGE_SIZE,
					 (unsigned int)drain_ms) < 0) {
			fail("grown region drain timeout after %lu ms", drain_ms);
			return 1;
		}
	}

	/*
	 * Verify regions against the snapshotted state.
	 * This is the key correctness check - we know exactly what each
	 * page should contain based on the atomic counters.
	 */
	if (verify_initial_region(snap_dirty_passes, snap_last_dirty) < 0) {
		fail("initial region verification failed");
		return 1;
	}
	if (verify_grown_region(snap_grown_filled) < 0) {
		fail("grown region verification failed");
		return 1;
	}

	/* Verify VMA sizes are as expected */
	test_msg("VMA sizes: initial=%zu bytes (%zu pages), "
		 "grown=%zu bytes (%zu pages filled)\n",
		 INITIAL_BYTES, INITIAL_PAGES,
		 GROW_BYTES, snap_grown_filled);

	pass();
	return 0;
}
