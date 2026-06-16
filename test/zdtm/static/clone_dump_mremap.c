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

const char *test_doc = "--clone-dump mremap test: "
		       "verifies UFFD_EVENT_REMAP detection when process "
		       "uses mremap() to move a memory region during Phase 2. "
		       "Without UFFD_EVENT_REMAP handling, pages at old address "
		       "would be sent but process expects them at new address.";
const char *test_author = "Asaf Porat Stoler <asafpor@gmail.com>";


/*
 * Region that gets mremap'd. 64 MB is enough to prove the bug.
 */
#define REGION_MB	64
#define REGION_BYTES	((size_t)REGION_MB << 20)
#define REGION_PAGES	(REGION_BYTES / PAGE_SIZE)

/*
 * Padding region keeps bulk transfer busy, giving mremap thread time
 * to move the region before Phase 3 freeze.
 */
#define PADDING_MB	512
#define PADDING_BYTES	((size_t)PADDING_MB << 20)
#define TOTAL_MB	(REGION_MB + PADDING_MB)
#define TOTAL_BYTES	(REGION_BYTES + PADDING_BYTES)

#define MARKER_ORIGINAL	0xAA
#define MARKER_MOVED	0xBB

/*
 * No sleep needed: the thread is frozen during Phase 1 and unfrozen when
 * Phase 2 begins. UFFD_EVENT_REMAP is delivered synchronously when mremap()
 * is called, regardless of bulk transfer progress. The padding region ensures
 * Phase 2 lasts long enough for the remap to complete before Phase 3 freeze.
 */

#define DRAIN_TIMEOUT_MS_PER_GB	10000UL

static unsigned char *region;
static unsigned char *blocker;	/* Blocks in-place growth, forces mremap to move */
static unsigned char *padding;
static unsigned char *moved_region;
static atomic_int    mremap_done;
static atomic_int    mremap_errno;

/*
 * mremap thread: moves the target region to a new address during Phase 2.
 *
 * Timeline:
 * - Phase 1: VMA at [A, A+64MB) tracked with 0xAA content
 * - Phase 2: Bulk transfer starts reading from A
 * - This thread wakes and does mremap(A, 64MB, 64MB, MREMAP_MAYMOVE)
 * - Kernel sends UFFD_EVENT_REMAP to CRIU
 * - Pages now at address B with same 0xAA content
 * - Thread writes 0xBB to some pages at new address
 * - Phase 3: CRIU should detect the remap and read from new address
 *
 * Without UFFD_EVENT_REMAP handling:
 * - CRIU thinks old address is unmapped (EFAULT on read)
 * - New address detected as "new VMA" but bulk already sent stale data
 * - Restored process gets wrong content or SIGBUS
 */
static void *mremap_thread(void *arg)
{
	unsigned char *new_addr;
	size_t i;

	/*
	 * No sleep - just do the mremap. This thread is frozen during Phase 1.
	 * When it unfreezes, Phase 2 is active and UFFD_EVENT_REMAP will be
	 * delivered. The padding region keeps Phase 2 going long enough.
	 */

	new_addr = mremap(region, REGION_BYTES, REGION_BYTES, MREMAP_MAYMOVE);
	if (new_addr == MAP_FAILED) {
		atomic_store(&mremap_errno, errno);
		pr_perror("mremap failed");
		return (void *)(intptr_t)-1;
	}

	if (new_addr == region) {
		/*
		 * If the blocker was placed correctly, this shouldn't happen.
		 * Not a test failure, but log it for debugging.
		 */
		test_msg("WARNING: mremap returned same address %p "
			 "(blocker may not have been adjacent)\n", new_addr);
	} else {
		test_msg("mremap moved region: %p -> %p (delta=%ld MB)\n",
			 region, new_addr,
			 (long)((new_addr - region) >> 20));
	}

	for (i = 0; i < REGION_PAGES; i += 4) {
		memset(new_addr + i * PAGE_SIZE, MARKER_MOVED, PAGE_SIZE);
	}

	moved_region = new_addr;
	atomic_store(&mremap_done, 1);
	return NULL;
}

/*
 * Verify the region after restore.
 *
 * Expected state:
 * - Pages at stride positions (0, 4, 8, ...): 0xBB (written after mremap)
 * - Other pages: 0xAA (original content, preserved by mremap)
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

	if (mincore((void *)moved_region, REGION_BYTES, (void *)vec) < 0) {
		test_msg("mincore failed: %s\n", strerror(errno));
		free(vec);
		return -1;
	}

	for (p = 0; p < REGION_PAGES; p++) {
		unsigned char *page = moved_region + p * PAGE_SIZE;
		unsigned char expected;
		int is_modified_page = (p % 4 == 0);

		if (!(vec[p] & 1)) {
			if (not_resident < 8)
				test_msg("page %zu: NOT RESIDENT\n", p);
			not_resident++;
			continue;
		}

		if (is_modified_page)
			expected = MARKER_MOVED;
		else
			expected = MARKER_ORIGINAL;

		for (j = 0; j < PAGE_SIZE; j++) {
			if (page[j] != expected) {
				if (bad < 8)
					test_msg("page %zu offset %zu: got 0x%02x "
						 "expected 0x%02x (modified=%d)\n",
						 p, j, page[j], expected,
						 is_modified_page);
				bad++;
				break;
			}
		}
	}

	free(vec);

	if (not_resident) {
		test_msg("BUG: %u/%zu pages not resident\n",
			 not_resident, (size_t)REGION_PAGES);
	}
	if (bad) {
		test_msg("ERROR: %u pages have unexpected content\n", bad);
	}

	if (not_resident || bad) {
		return -1;
	}

	test_msg("OK: all %zu pages correct at moved address %p\n",
		 (size_t)REGION_PAGES, moved_region);
	return 0;
}

int main(int argc, char **argv)
{
	pthread_t th;
	size_t i;
	unsigned long drain_ms;

	test_init(argc, argv);

	test_msg("clone_dump_mremap: REGION=%u MB (%zu pages), "
		 "PADDING=%u MB, TOTAL=%u MB\n",
		 (unsigned)REGION_MB, (size_t)REGION_PAGES,
		 (unsigned)PADDING_MB, (unsigned)TOTAL_MB);

	region = mmap(NULL, REGION_BYTES, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		pr_perror("mmap region");
		return 1;
	}

	/*
	 * Allocate a blocker region immediately after the main region.
	 * This forces mremap(MREMAP_MAYMOVE) to actually move the pages
	 * to a new address rather than keeping them in place.
	 */
	blocker = mmap(region + REGION_BYTES, PAGE_SIZE, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (blocker == MAP_FAILED) {
		/*
		 * MAP_FIXED_NOREPLACE may fail if address already taken.
		 * Try without the hint - we just need something allocated.
		 */
		blocker = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (blocker == MAP_FAILED) {
			pr_perror("mmap blocker");
			return 1;
		}
		test_msg("blocker at %p (not adjacent, mremap may not move)\n", blocker);
	} else {
		test_msg("blocker at %p (adjacent to region end %p)\n",
			 blocker, region + REGION_BYTES);
	}

	padding = mmap(NULL, PADDING_BYTES, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (padding == MAP_FAILED) {
		pr_perror("mmap padding");
		return 1;
	}

	for (i = 0; i < REGION_BYTES; i += PAGE_SIZE)
		memset(region + i, MARKER_ORIGINAL, PAGE_SIZE);

	for (i = 0; i < PADDING_BYTES; i += PAGE_SIZE)
		memset(padding + i, 0x55, PAGE_SIZE);

	moved_region = region;

	atomic_init(&mremap_done, 0);
	atomic_init(&mremap_errno, 0);

	if (pthread_create(&th, NULL, mremap_thread, NULL)) {
		pr_perror("pthread_create");
		return 1;
	}

	test_daemon();
	test_waitsig();

	pthread_join(th, NULL);

	if (atomic_load(&mremap_errno)) {
		fail("mremap thread failed: errno=%d", atomic_load(&mremap_errno));
		return 1;
	}

	if (!atomic_load(&mremap_done)) {
		fail("mremap thread did not complete before freeze");
		return 1;
	}

	drain_ms = DRAIN_TIMEOUT_MS_PER_GB * (TOTAL_MB / 1024UL + 1);
	if (clone_wait_for_drain(moved_region, REGION_BYTES,
			       (unsigned int)drain_ms) < 0) {
		test_msg("drain incomplete — verifying available pages\n");
	}

	if (verify_region() < 0) {
		fail("region verification failed after mremap");
		return 1;
	}

	pass();
	return 0;
}
