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

const char *test_doc = "--clone-dump WP_UNPOPULATED test: "
		       "verifies UFFD_FEATURE_WP_UNPOPULATED handling for pages "
		       "that are mmap'd but never touched (no PTE exists). "
		       "Without WP_UNPOPULATED, these pages cannot be WP-tracked "
		       "and writes during Phase 2 may be missed.";
const char *test_author = "Asaf Porat Stoler <asafpor@gmail.com>";


/*
 * Test strategy:
 * 1. mmap a large region but only touch SOME pages (creating PTEs for those)
 * 2. Leave other pages untouched (no PTE - "unpopulated")
 * 3. During Phase 2, write to some of the unpopulated pages
 * 4. Verify after restore that both originally-touched and newly-touched
 *    pages have correct content
 *
 * Without WP_UNPOPULATED:
 * - Unpopulated pages cannot have WP markers set
 * - PAGEMAP_SCAN won't see writes to these pages as "dirty"
 * - Phase 3 won't send the updated content
 * - Restored process sees zero instead of written data
 */

#define REGION_MB	128
#define REGION_BYTES	((size_t)REGION_MB << 20)
#define REGION_PAGES	(REGION_BYTES / PAGE_SIZE)

/*
 * Padding to keep bulk busy
 */
#define PADDING_MB	256
#define PADDING_BYTES	((size_t)PADDING_MB << 20)
#define TOTAL_MB	(REGION_MB + PADDING_MB)
#define TOTAL_BYTES	(REGION_BYTES + PADDING_BYTES)

/*
 * Only populate every Nth page initially. The rest stay unpopulated.
 * This means 75% of pages have no PTE at Phase 1 time.
 */
#define POPULATE_STRIDE	4

#define MARKER_POPULATED	0x11
#define MARKER_UNPOPULATED_WRITE 0x22

/*
 * No sleep needed: the thread is frozen during Phase 1 and unfrozen when
 * Phase 2 begins. Writes to unpopulated pages are tracked via WP_UNPOPULATED.
 * The padding region ensures Phase 2 lasts long enough.
 */

#define DRAIN_TIMEOUT_MS_PER_GB	10000UL

static unsigned char *region;
static unsigned char *padding;
static atomic_int    write_done;
static atomic_int    write_errno;

/*
 * Writer thread: writes to previously-unpopulated pages during Phase 2.
 *
 * These pages had no PTE at Phase 1 freeze time. With WP_UNPOPULATED,
 * the kernel can still track writes to them. Without it, writes would
 * be invisible to PAGEMAP_SCAN.
 */
static void *writer_thread(void *arg)
{
	size_t i;

	/*
	 * No sleep - just do the writes. This thread is frozen during Phase 1.
	 * When it unfreezes, Phase 2 is active. With WP_UNPOPULATED, writes to
	 * pages without PTEs are tracked. The padding keeps Phase 2 going.
	 */

	for (i = 1; i < REGION_PAGES; i += POPULATE_STRIDE) {
		memset(region + i * PAGE_SIZE, MARKER_UNPOPULATED_WRITE, PAGE_SIZE);
	}

	atomic_store(&write_done, 1);
	return NULL;
}

/*
 * Verify the region after restore.
 *
 * Expected state:
 * - Pages at stride 0, 4, 8, ... (populated before Phase 1): 0x11
 * - Pages at stride 1, 5, 9, ... (written during Phase 2): 0x22
 * - Pages at stride 2, 3, 6, 7, ... (never touched): 0x00
 */
static int verify_region(void)
{
	size_t p, j;
	unsigned int bad = 0, not_resident = 0;
	unsigned char *vec;

	vec = malloc(REGION_PAGES);
	if (!vec) {
		test_msg("malloc vec failed\n");
		return -1;
	}

	if (mincore((void *)region, REGION_BYTES, (void *)vec) < 0) {
		test_msg("mincore failed: %s\n", strerror(errno));
		free(vec);
		return -1;
	}

	for (p = 0; p < REGION_PAGES; p++) {
		unsigned char *page = region + p * PAGE_SIZE;
		unsigned char expected;
		int page_type;

		if (p % POPULATE_STRIDE == 0) {
			expected = MARKER_POPULATED;
			page_type = 0;
		} else if (p % POPULATE_STRIDE == 1) {
			expected = MARKER_UNPOPULATED_WRITE;
			page_type = 1;
		} else {
			expected = 0x00;
			page_type = 2;
		}

		if (!(vec[p] & 1)) {
			if (page_type != 2) {
				if (not_resident < 8)
					test_msg("page %zu: NOT RESIDENT "
						 "(type=%d)\n", p, page_type);
				not_resident++;
			}
			continue;
		}

		for (j = 0; j < PAGE_SIZE; j++) {
			if (page[j] != expected) {
				if (bad < 8)
					test_msg("page %zu offset %zu: got 0x%02x "
						 "expected 0x%02x (type=%d)\n",
						 p, j, page[j], expected, page_type);
				bad++;
				break;
			}
		}
	}

	free(vec);

	if (not_resident) {
		test_msg("BUG: %u pages not resident that should be\n",
			 not_resident);
	}
	if (bad) {
		test_msg("ERROR: %u pages have unexpected content\n", bad);
	}

	if (not_resident || bad) {
		return -1;
	}

	test_msg("OK: all pages correct (populated=%zu, unpop_written=%zu, zero=%zu)\n",
		 (size_t)(REGION_PAGES / POPULATE_STRIDE),
		 (size_t)(REGION_PAGES / POPULATE_STRIDE),
		 (size_t)(REGION_PAGES - 2 * (REGION_PAGES / POPULATE_STRIDE)));
	return 0;
}

int main(int argc, char **argv)
{
	pthread_t th;
	size_t i;
	unsigned long drain_ms;

	test_init(argc, argv);

	test_msg("clone_dump_wp_unpopulated: REGION=%u MB (%zu pages), "
		 "PADDING=%u MB, POPULATE_STRIDE=%d\n",
		 (unsigned)REGION_MB, (size_t)REGION_PAGES,
		 (unsigned)PADDING_MB, POPULATE_STRIDE);

	region = mmap(NULL, REGION_BYTES, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		pr_perror("mmap region");
		return 1;
	}

	padding = mmap(NULL, PADDING_BYTES, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (padding == MAP_FAILED) {
		pr_perror("mmap padding");
		return 1;
	}

	for (i = 0; i < REGION_PAGES; i += POPULATE_STRIDE)
		memset(region + i * PAGE_SIZE, MARKER_POPULATED, PAGE_SIZE);

	for (i = 0; i < PADDING_BYTES; i += PAGE_SIZE)
		memset(padding + i, 0x55, PAGE_SIZE);

	atomic_init(&write_done, 0);
	atomic_init(&write_errno, 0);

	if (pthread_create(&th, NULL, writer_thread, NULL)) {
		pr_perror("pthread_create");
		return 1;
	}

	test_daemon();
	test_waitsig();

	pthread_join(th, NULL);

	if (atomic_load(&write_errno)) {
		fail("writer thread failed: errno=%d", atomic_load(&write_errno));
		return 1;
	}

	if (!atomic_load(&write_done)) {
		fail("writer thread did not complete before freeze");
		return 1;
	}

	drain_ms = DRAIN_TIMEOUT_MS_PER_GB * (TOTAL_MB / 1024UL + 1);
	if (clone_wait_for_drain(region, REGION_BYTES,
			       (unsigned int)drain_ms) < 0) {
		test_msg("drain incomplete — verifying available pages\n");
	}

	if (verify_region() < 0) {
		fail("region verification failed — "
		     "unpopulated page writes not restored correctly");
		return 1;
	}

	pass();
	return 0;
}
