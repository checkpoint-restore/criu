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

const char *test_doc = "--clone-dump munmap+reuse test: allocates a large "
		       "anon-private region, fills it, then during Phase 2 "
		       "a background thread munmaps the region and immediately "
		       "re-maps fresh pages at the same address with a new "
		       "marker. After restore the region must carry the new "
		       "marker on every page (source must detect the reused "
		       "pages as new/dirty, not serve stale pre-dump content).";
const char *test_author = "Asaf Porat Stoler <asafpor@gmail.com>";


/*
 * Default 32 GB. Override at build time with -DCLONE_MUNMAP_REUSE_MB=N.
 */
#ifndef CLONE_MUNMAP_REUSE_MB
#define CLONE_MUNMAP_REUSE_MB	32768		/* 32 GB */
#endif
#define REGION_MB		CLONE_MUNMAP_REUSE_MB
#define REGION_BYTES		((size_t)REGION_MB << 20)
#define REGION_PAGES		(REGION_BYTES / PAGE_SIZE)

#define MARKER_ORIGINAL		0x11
#define MARKER_REUSED		0xBB

#define DRAIN_TIMEOUT_MS_PER_GB	10000UL

static unsigned char *region;
static atomic_int    stop_workers;
static atomic_int    reuse_done;		/* set after remap + fill */
static atomic_int    reuse_errno;		/* non-zero on failure */

/*
 * Reuser thread: munmaps the original region, then re-maps at the SAME
 * address with MAP_FIXED, fills with MARKER_REUSED. This exercises two
 * things on the source side:
 *
 *   1. UFFD REMOVE event fires for the munmap → source marks pages
 *      unmapped and drops them from the buffer.
 *
 *   2. The new mmap at the same address either:
 *      (a) creates a new VMA that the source hasn't WP-registered → the
 *          source discovers it in Phase 3 via /proc/pid/maps diff, or
 *      (b) if the process writes to those pages before Phase 3, the
 *          writes don't trigger WP faults (no WP registration on new VMA)
 *          so the source must read them fresh in the Phase 3 bulk send.
 *
 * Either way, the target must see MARKER_REUSED, NOT MARKER_ORIGINAL.
 * If the source incorrectly serves stale buffered pages, the target sees
 * 0x11 instead of 0xBB.
 */
static void *reuser_thread(void *arg)
{
	unsigned char *addr = region;
	unsigned char *buf;
	size_t i;

	/*
	 * No sleep needed - the thread is frozen during Phase 1 and unfrozen
	 * when Phase 2 begins. UFFD_EVENT_UNMAP is delivered synchronously
	 * when munmap() is called. The large region size (32GB default) ensures
	 * Phase 2 lasts long enough for the remap to complete.
	 */

	if (munmap(addr, REGION_BYTES) < 0) {
		atomic_store(&reuse_errno, errno);
		pr_perror("reuser munmap");
		return (void *)(intptr_t)-1;
	}

	/*
	 * Re-map at the same address with MAP_FIXED. This guarantees the
	 * new VMA occupies exactly the same virtual range.
	 */
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

	/* Fill with new marker page by page. */
	for (i = 0; i < REGION_BYTES; i += PAGE_SIZE) {
		if (atomic_load(&stop_workers))
			break;
		memset(buf + i, MARKER_REUSED, PAGE_SIZE);
	}

	/* Update the global pointer and signal completion. */
	region = buf;
	atomic_store(&reuse_done, 1);

	/* Idle until stopped. */
	while (!atomic_load(&stop_workers))
		usleep(1000);
	return NULL;
}

static int verify_region(void)
{
	size_t p, j;
	unsigned int bad_marker = 0, torn = 0, stale = 0;

	for (p = 0; p < REGION_PAGES; p++) {
		unsigned char *page = region + p * PAGE_SIZE;
		unsigned char m = page[0];

		if (m == MARKER_ORIGINAL) {
			if (stale < 8)
				test_msg("page %zu: STALE marker 0x%02x (source served old data)\n",
					 p, m);
			stale++;
			continue;
		}
		if (m != MARKER_REUSED) {
			if (bad_marker < 8)
				test_msg("page %zu: unexpected marker 0x%02x\n", p, m);
			bad_marker++;
			continue;
		}
		for (j = 1; j < PAGE_SIZE; j++) {
			if (page[j] != m) {
				if (torn < 8)
					test_msg("page %zu: torn at offset %zu (0x%02x != 0x%02x)\n",
						 p, j, page[j], m);
				torn++;
				break;
			}
		}
	}

	if (stale) {
		test_msg("CRITICAL: %u pages still have MARKER_ORIGINAL — "
			 "source served stale pre-munmap data!\n", stale);
	}
	if (bad_marker || torn || stale) {
		test_msg("summary: stale=%u bad_marker=%u torn=%u pages=%zu\n",
			 stale, bad_marker, torn, REGION_PAGES);
		return -1;
	}
	test_msg("OK: all %zu pages carry MARKER_REUSED with no torn writes\n",
		 REGION_PAGES);
	return 0;
}

int main(int argc, char **argv)
{
	pthread_t th;
	size_t i;
	unsigned long drain_ms;

	test_init(argc, argv);

	test_msg("clone_dump_munmap_reuse: REGION=%u MB (%zu pages)\n",
		 (unsigned)REGION_MB, (size_t)REGION_PAGES);

	region = mmap(NULL, REGION_BYTES, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		pr_perror("initial mmap %zu bytes", REGION_BYTES);
		return 1;
	}
	for (i = 0; i < REGION_BYTES; i += PAGE_SIZE)
		memset(region + i, MARKER_ORIGINAL, PAGE_SIZE);

	atomic_init(&stop_workers, 0);
	atomic_init(&reuse_done, 0);
	atomic_init(&reuse_errno, 0);

	if (pthread_create(&th, NULL, reuser_thread, NULL)) {
		pr_perror("pthread_create reuser");
		return 1;
	}

	test_daemon();
	test_waitsig();

	/* Wait for the reuser to finish filling the new region. */
	while (!atomic_load(&reuse_done))
		usleep(10 * 1000);

	atomic_store(&stop_workers, 1);
	pthread_join(th, NULL);

	if (atomic_load(&reuse_errno)) {
		fail("reuser thread failed: errno=%d", atomic_load(&reuse_errno));
		return 1;
	}

	/* Drain gate: wait for all pages to be resident. */
	drain_ms = DRAIN_TIMEOUT_MS_PER_GB * (REGION_MB / 1024UL + 1);
	if (clone_wait_for_drain(region, REGION_BYTES,
			       (unsigned int)drain_ms) < 0) {
		fail("drain did not complete within %lu ms", drain_ms);
		return 1;
	}

	if (verify_region() < 0) {
		fail("region verification failed");
		return 1;
	}

	pass();
	return 0;
}
