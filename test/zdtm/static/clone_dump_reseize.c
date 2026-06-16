#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "zdtmtst.h"
#include "clone_dump_util.h"

const char *test_doc = "--clone-dump reseize stress: concurrent VMA churn during "
		       "dump exercises Phase 2->3 re-seize. Tracks stable region "
		       "state and churn thread activity to detect corruption.";
const char *test_author = "Asaf Porat Stoler <asafpor@gmail.com>";


#define STABLE_PAGES	1024
#define CHURN_THREADS	4
#define CHURN_PAGES	8
#define DRAIN_TIMEOUT	10000

static atomic_int stop_churn;
static atomic_size_t total_churn_cycles;

/* Unique pattern for each stable page */
static inline unsigned char stable_marker(int page_idx, int offset)
{
	return (unsigned char)((page_idx * 13 + offset) & 0xff);
}

static void *churn_thread(void *arg)
{
	size_t local_cycles = 0;

	while (!atomic_load(&stop_churn)) {
		unsigned char *p;

		p = mmap(NULL, CHURN_PAGES * PAGE_SIZE, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p == MAP_FAILED)
			continue;
		memset(p, 0xa5, CHURN_PAGES * PAGE_SIZE);
		mprotect(p, PAGE_SIZE, PROT_READ);
		mprotect(p, PAGE_SIZE, PROT_READ | PROT_WRITE);
		munmap(p, CHURN_PAGES * PAGE_SIZE);
		local_cycles++;
	}

	atomic_fetch_add(&total_churn_cycles, local_cycles);
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t th[CHURN_THREADS];
	unsigned char *stable;
	unsigned long sz = STABLE_PAGES * PAGE_SIZE;
	int i, j;
	int errors = 0;
	int first_error = -1, last_error = -1;
	size_t snap_churn;

	test_init(argc, argv);

	stable = mmap(NULL, sz, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (stable == MAP_FAILED) {
		pr_perror("mmap stable");
		return 1;
	}

	/* Fill with per-page, per-offset pattern */
	for (i = 0; i < STABLE_PAGES; i++) {
		unsigned char *page = stable + i * PAGE_SIZE;
		for (j = 0; j < PAGE_SIZE; j++)
			page[j] = stable_marker(i, j);
	}

	atomic_init(&stop_churn, 0);
	atomic_init(&total_churn_cycles, 0);

	for (i = 0; i < CHURN_THREADS; i++) {
		if (pthread_create(&th[i], NULL, churn_thread, NULL)) {
			pr_perror("pthread_create");
			return 1;
		}
	}

	test_daemon();
	test_waitsig();

	snap_churn = atomic_load(&total_churn_cycles);

	atomic_store(&stop_churn, 1);
	for (i = 0; i < CHURN_THREADS; i++)
		pthread_join(th[i], NULL);

	test_msg("State at restore: churn_cycles=%zu (across %d threads)\n",
		 snap_churn, CHURN_THREADS);

	if (clone_wait_for_drain(stable, sz, DRAIN_TIMEOUT) < 0) {
		fail("stable region drain timeout");
		return 1;
	}

	/* Verify stable region byte-by-byte */
	for (i = 0; i < STABLE_PAGES; i++) {
		unsigned char *page = stable + i * PAGE_SIZE;
		int page_ok = 1;

		for (j = 0; j < PAGE_SIZE; j++) {
			unsigned char expected = stable_marker(i, j);
			if (page[j] != expected) {
				if (errors < 8)
					test_msg("stable page %d offset %d: "
						 "got 0x%02x expected 0x%02x\n",
						 i, j, page[j], expected);
				page_ok = 0;
				break;
			}
		}

		if (!page_ok) {
			if (first_error < 0)
				first_error = i;
			last_error = i;
			errors++;
		}
	}

	if (errors) {
		test_msg("SUMMARY: %d/%d stable pages corrupted, "
			 "first=%d last=%d, churn=%zu\n",
			 errors, STABLE_PAGES, first_error, last_error, snap_churn);
		fail("reseize stress test failed");
		return 1;
	}

	test_msg("OK: all %d stable pages verified, %zu churn cycles\n",
		 STABLE_PAGES, snap_churn);
	pass();
	return 0;
}
