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

const char *test_doc = "--clone-dump shrinkage test: two equally-sized anon-private "
		       "regions filled pre-dump; during Phase 2 a background "
		       "thread munmaps the 'drop' region wholesale. After "
		       "restore the 'kept' region must survive byte-exact and "
		       "the dropped range must no longer be mapped. Exercises "
		       "the UFFD REMOVE-event handler "
		       "(clone_handle_remove_event) at working-set scale.";
const char *test_author = "Asaf Porat Stoler <asafpor@gmail.com>";


/*
 * Default 256 MB total (128 MB kept + 128 MB dropped) for CI.
 * Override at build time with -DCLONE_MUNMAP_HALF_MB=N for scale runs
 * (user's target: 32768 MB = 32 GB total, 16 GB kept + 16 GB munmap'd).
 */
#ifndef CLONE_MUNMAP_HALF_MB
#define CLONE_MUNMAP_HALF_MB	32768		/* 32 GB total (16 GB kept + 16 GB drop) */
#endif
#define TOTAL_MB		CLONE_MUNMAP_HALF_MB
#define HALF_BYTES		(((size_t)TOTAL_MB << 20) / 2)
#define HALF_PAGES		(HALF_BYTES / PAGE_SIZE)

#define MARKER_KEPT		0x55
#define MARKER_DROP		0xAA

#define DRAIN_TIMEOUT_MS_PER_GB	10000UL

static unsigned char *kept_region;
static unsigned char *drop_region;
static atomic_int    stop_workers;
static atomic_int    munmap_errno;	/* non-zero on munmap failure */

/*
 * Munmapper thread: one-shot. No sleep needed - the thread is frozen during
 * Phase 1 and unfrozen when Phase 2 begins. UFFD_EVENT_UNMAP is delivered
 * synchronously when munmap() is called. The kept region serves as padding
 * to ensure Phase 2 lasts long enough.
 *
 * This triggers a UFFD REMOVE event covering the full DROP_BYTES range,
 * which CRIU routes through clone_handle_remove_event ->
 * page_state_mark_range_unmapped + unmapped_tracker_mark_range +
 * clone_page_buffer_remove_range.
 */
static void *munmapper_thread(void *arg)
{
	/*
	 * No sleep - just do the munmap. UFFD events are synchronous.
	 */

	if (munmap(drop_region, HALF_BYTES) < 0) {
		atomic_store(&munmap_errno, errno);
		pr_perror("munmap drop region");
		return (void *)(intptr_t)-1;
	}
	/* Publish the drop by nulling the pointer so the verify path knows. */
	drop_region = NULL;

	/* Idle until stopped so the thread exists across Phase 2/3 freeze. */
	while (!atomic_load(&stop_workers))
		usleep(1000);
	return NULL;
}

static int verify_kept(void)
{
	size_t p, j;
	unsigned int bad_marker = 0, torn = 0;

	for (p = 0; p < HALF_PAGES; p++) {
		unsigned char *page = kept_region + p * PAGE_SIZE;
		unsigned char m = page[0];

		if (m != MARKER_KEPT) {
			if (bad_marker < 8)
				test_msg("kept page %zu: marker 0x%02x != 0x%02x\n",
					 p, m, MARKER_KEPT);
			bad_marker++;
			continue;
		}
		for (j = 1; j < PAGE_SIZE; j++) {
			if (page[j] != m) {
				if (torn < 8)
					test_msg("kept page %zu: torn at offset %zu (0x%02x != 0x%02x)\n",
						 p, j, page[j], m);
				torn++;
				break;
			}
		}
	}

	if (bad_marker || torn) {
		test_msg("kept summary: bad_marker=%u torn=%u pages=%zu\n",
			 bad_marker, torn, HALF_PAGES);
		return -1;
	}
	test_msg("kept OK: all %zu pages carry MARKER_KEPT with no torn writes\n",
		 HALF_PAGES);
	return 0;
}

/*
 * Confirm the dropped range is no longer mapped after restore. mincore
 * returns -1 / ENOMEM when any address in the range lacks a mapping,
 * which is the signal we want: the restore side recreated the address
 * space with the hole, not with a ghost mapping full of zeros.
 */
static int verify_drop_is_gone(void *addr)
{
	unsigned char probe;

	errno = 0;
	if (mincore(addr, HALF_BYTES, &probe) == 0) {
		test_msg("drop range still mapped after restore: addr=%p len=%zu\n",
			 addr, HALF_BYTES);
		return -1;
	}
	if (errno != ENOMEM) {
		test_msg("drop range mincore returned unexpected errno=%d (want ENOMEM)\n",
			 errno);
		return -1;
	}
	test_msg("drop range correctly unmapped after restore (mincore -> ENOMEM)\n");
	return 0;
}

int main(int argc, char **argv)
{
	pthread_t th;
	size_t i;
	unsigned long drain_ms;
	void *drop_addr_saved;
	int err = 0;

	test_init(argc, argv);

	test_msg("clone_dump_munmap_half: TOTAL=%u MB (kept=%zu MB, drop=%zu MB)\n",
		 (unsigned)TOTAL_MB,
		 (size_t)(HALF_BYTES >> 20),
		 (size_t)(HALF_BYTES >> 20));

	kept_region = mmap(NULL, HALF_BYTES, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (kept_region == MAP_FAILED) {
		pr_perror("mmap kept %zu bytes", HALF_BYTES);
		return 1;
	}
	drop_region = mmap(NULL, HALF_BYTES, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (drop_region == MAP_FAILED) {
		pr_perror("mmap drop %zu bytes", HALF_BYTES);
		return 1;
	}
	drop_addr_saved = drop_region;

	for (i = 0; i < HALF_BYTES; i += PAGE_SIZE)
		memset(kept_region + i, MARKER_KEPT, PAGE_SIZE);
	for (i = 0; i < HALF_BYTES; i += PAGE_SIZE)
		memset(drop_region + i, MARKER_DROP, PAGE_SIZE);

	atomic_init(&stop_workers, 0);
	atomic_init(&munmap_errno, 0);

	if (pthread_create(&th, NULL, munmapper_thread, NULL)) {
		pr_perror("pthread_create munmapper");
		return 1;
	}

	test_daemon();
	test_waitsig();

	atomic_store(&stop_workers, 1);
	pthread_join(th, NULL);

	if (atomic_load(&munmap_errno)) {
		fail("munmapper thread failed: errno=%d",
		     atomic_load(&munmap_errno));
		return 1;
	}
	if (drop_region != NULL) {
		fail("munmapper thread did not publish munmap completion "
		     "(it may not have run during Phase 2)");
		return 1;
	}

	/* Drain gate applies to the surviving region only. */
	drain_ms = DRAIN_TIMEOUT_MS_PER_GB *
		   ((HALF_BYTES >> 30) + 1);
	if (clone_wait_for_drain(kept_region, HALF_BYTES,
			       (unsigned int)drain_ms) < 0) {
		fail("kept region drain did not complete within %lu ms",
		     drain_ms);
		return 1;
	}

	if (verify_kept() < 0)
		err = 1;
	if (verify_drop_is_gone(drop_addr_saved) < 0)
		err = 1;

	if (err) {
		fail("clone_dump_munmap_half verification failed");
		return 1;
	}

	pass();
	return 0;
}
