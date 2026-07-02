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

const char *test_doc = "--clone-dump munmap+reuse with UNWRITTEN pages: "
		       "exposes bug where munmap+mmap at same address leaves "
		       "zero-fill-on-demand pages that PAGEMAP_SCAN cannot see "
		       "(no PTE → no PAGE_IS_WRITTEN). Without fix, restored "
		       "process gets stale data from bulk transfer.";
const char *test_author = "Asaf Porat Stoler <asafpor@gmail.com>";


/*
 * Target region that gets remapped. 64 MB is enough to prove the bug.
 */
#ifndef CLONE_MUNMAP_REUSE_UNWRITTEN_MB
#define CLONE_MUNMAP_REUSE_UNWRITTEN_MB	64
#endif
#define REGION_MB	CLONE_MUNMAP_REUSE_UNWRITTEN_MB
#define REGION_BYTES	((size_t)REGION_MB << 20)
#define REGION_PAGES	(REGION_BYTES / PAGE_SIZE)

/*
 * Padding region keeps bulk transfer busy after it reads the target,
 * giving the reuser thread time to remap before Phase 3 freeze.
 * Without padding, the window between "bulk done with target" and
 * "process frozen" is only ~7ms — too tight for reliable reproduction.
 */
#define PADDING_MB	512
#define PADDING_BYTES	((size_t)PADDING_MB << 20)
#define TOTAL_MB	(REGION_MB + PADDING_MB)
#define TOTAL_BYTES	(REGION_BYTES + PADDING_BYTES)

#define MARKER_ORIGINAL	0x11
#define MARKER_WRITTEN	0xCC

/*
 * Only write every Nth page after remap. The rest stay as zero-fill-on-demand.
 * Writing every 4th page means 75% of pages have no PTE after remap.
 */
#define WRITE_STRIDE	4

/*
 * No sleep needed: the thread is frozen during Phase 1 and unfrozen when
 * Phase 2 begins. UFFD_EVENT_UNMAP is delivered synchronously when munmap()
 * is called, regardless of bulk transfer progress. The padding region ensures
 * Phase 2 lasts long enough for the remap to complete before Phase 3 freeze.
 */

#define DRAIN_TIMEOUT_MS_PER_GB	10000UL

static unsigned char *full_region;
static unsigned char *region;
static atomic_int    reuse_done;
static atomic_int    reuse_errno;

/*
 * Reuser thread: munmaps the target portion (first 64MB), re-maps at
 * the SAME address, and only writes SOME pages. The padding (remaining
 * 512MB) stays intact and keeps bulk busy.
 *
 * Timing is critical:
 * - Phase 1 freeze captures the FULL 576MB VMA with 0x11 content
 * - Bulk reads the target portion first (lower address), sending 0x11
 * - This thread wakes AFTER bulk has read the target but BEFORE freeze
 * - munmap destroys the uffd-WP registration for the target portion
 * - mmap(MAP_FIXED) creates a NEW unregistered VMA at the same address
 * - Writes to stride pages put 0xCC; unwritten pages stay zero-fill
 *
 * The bug: clone_detect_new_vmas() uses address-only comparison. The
 * tracked VMA [A, A+576MB) covers [A, A+64MB), so it's not flagged new.
 * The scanner can't detect dirty pages (VMA not uffd-registered).
 * Result: primary only sends the stale 0x11 bulk data for this range.
 */
static void *reuser_thread(void *arg)
{
	unsigned char *addr = region;
	unsigned char *buf;
	size_t i;

	/*
	 * No sleep - just do the remap. This thread is frozen during Phase 1.
	 * When it unfreezes, Phase 2 is active and UFFD events will be
	 * delivered. The padding region keeps Phase 2 going long enough.
	 */

	if (munmap(addr, REGION_BYTES) < 0) {
		atomic_store(&reuse_errno, errno);
		pr_perror("reuser munmap");
		return (void *)(intptr_t)-1;
	}

	buf = mmap(addr, REGION_BYTES, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (buf == MAP_FAILED) {
		atomic_store(&reuse_errno, errno);
		pr_perror("reuser remap at %p", addr);
		return (void *)(intptr_t)-1;
	}
	if (buf != addr) {
		atomic_store(&reuse_errno, ENOMEM);
		pr_err("reuser: MAP_FIXED returned %p != %p\n", buf, addr);
		return (void *)(intptr_t)-1;
	}

	for (i = 0; i < REGION_PAGES; i += WRITE_STRIDE) {
		memset(buf + i * PAGE_SIZE, MARKER_WRITTEN, PAGE_SIZE);
	}

	region = buf;
	atomic_store(&reuse_done, 1);
	return NULL;
}

/*
 * Verify the region after restore.
 *
 * Uses mincore to check residency first — non-resident pages indicate
 * the bug (pages should be delivered by drain or page fault). Accessing
 * a non-resident page when lazy-pages has exited causes SIGBUS.
 *
 * Expected state for correct behavior:
 * - Pages at stride positions: 0xCC (written by reuser after remap)
 * - Other pages: 0x00 (zero-fill-on-demand after remap)
 *
 * Bug manifestation (any of):
 * - Non-resident pages (drain failed to serve them → SIGBUS on access)
 * - Stride pages with 0x11 (stale bulk data from before remap)
 * - Zero-fill pages with 0x11 (stale bulk data)
 */
static int verify_region(void)
{
	size_t p, j;
	unsigned int stale = 0, bad = 0, not_resident = 0;
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
		int is_written_page = (p % WRITE_STRIDE == 0);

		if (!(vec[p] & 1)) {
			if (not_resident < 8)
				test_msg("page %zu: NOT RESIDENT "
					 "(written_page=%d) — bug: "
					 "drain/fault failed\n",
					 p, is_written_page);
			not_resident++;
			continue;
		}

		if (is_written_page)
			expected = MARKER_WRITTEN;
		else
			expected = 0x00;

		if (page[0] == MARKER_ORIGINAL) {
			if (stale < 8)
				test_msg("page %zu: STALE 0x%02x "
					 "(bulk served pre-remap data)\n",
					 p, page[0]);
			stale++;
			continue;
		}

		if (page[0] != expected) {
			if (bad < 8)
				test_msg("page %zu: got 0x%02x expected 0x%02x "
					 "(written_page=%d)\n",
					 p, page[0], expected, is_written_page);
			bad++;
			continue;
		}

		for (j = 1; j < PAGE_SIZE; j++) {
			if (page[j] != expected) {
				if (bad < 8)
					test_msg("page %zu offset %zu: got "
						 "0x%02x expected 0x%02x\n",
						 p, j, page[j], expected);
				bad++;
				break;
			}
		}
	}

	free(vec);

	if (not_resident) {
		test_msg("BUG: %u/%zu pages not resident — "
			 "remap not detected, pages never served\n",
			 not_resident, (size_t)REGION_PAGES);
	}
	if (stale) {
		test_msg("BUG: %u pages have MARKER_ORIGINAL 0x%02x — "
			 "bulk served stale pre-remap data\n",
			 stale, MARKER_ORIGINAL);
	}
	if (bad) {
		test_msg("ERROR: %u pages have unexpected content\n", bad);
	}

	if (not_resident || stale || bad) {
		test_msg("summary: not_resident=%u stale=%u bad=%u "
			 "(total=%zu stride=%zu zero_fill=%zu)\n",
			 not_resident, stale, bad,
			 (size_t)REGION_PAGES,
			 (size_t)(REGION_PAGES / WRITE_STRIDE),
			 (size_t)(REGION_PAGES - REGION_PAGES / WRITE_STRIDE));
		return -1;
	}

	test_msg("OK: all %zu pages correct "
		 "(%zu written=0x%02x, %zu zero-fill)\n",
		 (size_t)REGION_PAGES,
		 (size_t)(REGION_PAGES / WRITE_STRIDE), MARKER_WRITTEN,
		 (size_t)(REGION_PAGES - REGION_PAGES / WRITE_STRIDE));
	return 0;
}

int main(int argc, char **argv)
{
	pthread_t th;
	size_t i;
	unsigned long drain_ms;

	test_init(argc, argv);

	test_msg("clone_dump_munmap_reuse_unwritten: TARGET=%u MB (%zu pages), "
		 "PADDING=%u MB, TOTAL=%u MB, WRITE_STRIDE=%d\n",
		 (unsigned)REGION_MB, (size_t)REGION_PAGES,
		 (unsigned)PADDING_MB, (unsigned)TOTAL_MB,
		 WRITE_STRIDE);

	/*
	 * Allocate TARGET + PADDING as one contiguous region.
	 * The TARGET (first 64MB) is what gets remapped.
	 * The PADDING (remaining 512MB) keeps bulk transfer busy so
	 * the remap can happen AFTER bulk reads the target but BEFORE freeze.
	 */
	full_region = mmap(NULL, TOTAL_BYTES, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (full_region == MAP_FAILED) {
		pr_perror("initial mmap %zu bytes", TOTAL_BYTES);
		return 1;
	}
	region = full_region;

	for (i = 0; i < TOTAL_BYTES; i += PAGE_SIZE)
		memset(full_region + i, MARKER_ORIGINAL, PAGE_SIZE);

	atomic_init(&reuse_done, 0);
	atomic_init(&reuse_errno, 0);

	if (pthread_create(&th, NULL, reuser_thread, NULL)) {
		pr_perror("pthread_create reuser");
		return 1;
	}

	test_daemon();
	test_waitsig();

	pthread_join(th, NULL);

	if (atomic_load(&reuse_errno)) {
		fail("reuser thread failed: errno=%d", atomic_load(&reuse_errno));
		return 1;
	}

	if (!atomic_load(&reuse_done)) {
		fail("reuser thread did not complete before freeze");
		return 1;
	}

	drain_ms = DRAIN_TIMEOUT_MS_PER_GB * (TOTAL_MB / 1024UL + 1);
	if (clone_wait_for_drain(region, REGION_BYTES,
			       (unsigned int)drain_ms) < 0) {
		test_msg("drain incomplete — verifying available pages\n");
	}

	if (verify_region() < 0) {
		fail("region verification failed — "
		     "unwritten pages not restored correctly");
		return 1;
	}

	pass();
	return 0;
}
