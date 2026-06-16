#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "zdtmtst.h"
#include "clone_dump_util.h"

const char *test_doc = "--clone-dump new-VMA handling: tracks exactly which VMAs "
		       "were created and their expected content. Classifies each "
		       "as present+correct, present+corrupt, or missing.";
const char *test_author = "Asaf Porat Stoler <asafpor@gmail.com>";


#define STABLE_PAGES	256
#define NEW_VMA_PAGES	4
#define TRACKED_MAX	1024
#define DRAIN_TIMEOUT	10000

#define HINT_BASE	((unsigned long)0x500000000000UL)
#define HINT_STRIDE	((unsigned long)(2UL << 20))

struct tracked_vma {
	void *ptr;
	size_t len;
	unsigned char marker;
	int initialized;
};

static struct tracked_vma *g_tracked;
static atomic_uint g_next;
static atomic_int g_stop;

/* Stable region uses per-page, per-offset pattern */
static inline unsigned char stable_marker(int page_idx, int offset)
{
	return (unsigned char)((page_idx * 17 + offset) & 0xff);
}

static void *mapper_thread(void *arg)
{
	while (!atomic_load(&g_stop)) {
		unsigned int idx;
		void *p;
		unsigned char m;

		idx = atomic_fetch_add(&g_next, 1);
		if (idx >= TRACKED_MAX) {
			atomic_fetch_sub(&g_next, 1);
			usleep(10 * 1000);
			continue;
		}

		{
			void *hint = (void *)(HINT_BASE + (unsigned long)idx * HINT_STRIDE);
			p = mmap(hint, NEW_VMA_PAGES * PAGE_SIZE,
				 PROT_READ | PROT_WRITE,
				 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (p == MAP_FAILED) {
				atomic_fetch_sub(&g_next, 1);
				usleep(1000);
				continue;
			}
		}

		m = (unsigned char)((idx & 0x7f) | 0x80);
		memset(p, m, NEW_VMA_PAGES * PAGE_SIZE);

		g_tracked[idx].len = NEW_VMA_PAGES * PAGE_SIZE;
		g_tracked[idx].marker = m;
		g_tracked[idx].ptr = p;
		g_tracked[idx].initialized = 1;

		usleep(500);
	}
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t th;
	unsigned char *stable;
	unsigned long stable_sz = STABLE_PAGES * PAGE_SIZE;
	unsigned int nr_tracked;
	unsigned int i, j;
	unsigned int stable_errors = 0;
	unsigned int new_present_ok = 0;
	unsigned int new_present_corrupt = 0;
	unsigned int new_missing = 0;
	unsigned int new_uninitialized = 0;
	size_t tlist_bytes, tlist_pages;
	int first_stable_error = -1;

	test_init(argc, argv);

	stable = mmap(NULL, stable_sz, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (stable == MAP_FAILED) {
		pr_perror("mmap stable");
		return 1;
	}

	/* Fill stable region with tracked pattern */
	for (i = 0; i < STABLE_PAGES; i++) {
		unsigned char *page = stable + i * PAGE_SIZE;
		for (j = 0; j < PAGE_SIZE; j++)
			page[j] = stable_marker(i, j);
	}

	g_tracked = (struct tracked_vma *)stable;
	memset(g_tracked, 0, TRACKED_MAX * sizeof(*g_tracked));
	atomic_init(&g_next, 0);
	atomic_init(&g_stop, 0);

	tlist_bytes = (size_t)TRACKED_MAX * sizeof(*g_tracked);
	tlist_pages = (tlist_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

	if (pthread_create(&th, NULL, mapper_thread, NULL)) {
		pr_perror("pthread_create");
		return 1;
	}

	test_daemon();
	test_waitsig();

	nr_tracked = atomic_load(&g_next);
	if (nr_tracked > TRACKED_MAX)
		nr_tracked = TRACKED_MAX;

	atomic_store(&g_stop, 1);
	pthread_join(th, NULL);

	test_msg("State at restore: nr_tracked=%u\n", nr_tracked);

	if (clone_wait_for_drain(stable, stable_sz, DRAIN_TIMEOUT) < 0) {
		fail("stable-region drain timeout");
		return 1;
	}

	/* Verify stable region (skipping tracked-list overlay) */
	for (i = tlist_pages; i < STABLE_PAGES; i++) {
		unsigned char *page = stable + i * PAGE_SIZE;

		for (j = 0; j < PAGE_SIZE; j++) {
			unsigned char expected = stable_marker(i, j);
			if (page[j] != expected) {
				if (stable_errors < 8)
					test_msg("stable page %u offset %u: "
						 "got 0x%02x expected 0x%02x\n",
						 i, j, page[j], expected);
				if (first_stable_error < 0)
					first_stable_error = i;
				stable_errors++;
				break;
			}
		}
	}

	/* Classify tracked VMAs */
	for (i = 0; i < nr_tracked; i++) {
		struct tracked_vma *tv = &g_tracked[i];
		unsigned char vec[NEW_VMA_PAGES];
		unsigned char *base;
		int corrupt = 0;
		size_t p;

		if (!tv->initialized || tv->ptr == NULL) {
			new_uninitialized++;
			continue;
		}

		if (mincore(tv->ptr, tv->len, (void *)vec) == -1) {
			if (errno == ENOMEM) {
				new_missing++;
				continue;
			}
			continue;
		}

		base = tv->ptr;
		for (p = 0; p < tv->len / PAGE_SIZE; p++) {
			if (base[p * PAGE_SIZE] != tv->marker) {
				corrupt = 1;
				if (new_present_corrupt < 8)
					test_msg("tracked[%u] page %zu: "
						 "got 0x%02x expected 0x%02x\n",
						 i, p, base[p * PAGE_SIZE], tv->marker);
				break;
			}
		}
		if (corrupt)
			new_present_corrupt++;
		else
			new_present_ok++;
	}

	test_msg("RESULT: stable_errors=%u (first=%d) tracked=%u "
		 "present_ok=%u present_corrupt=%u missing=%u uninit=%u\n",
		 stable_errors, first_stable_error, nr_tracked,
		 new_present_ok, new_present_corrupt, new_missing, new_uninitialized);

	if (stable_errors) {
		fail("%u stable pages corrupted", stable_errors);
		return 1;
	}
	if (nr_tracked == 0) {
		fail("no tracked VMAs - test did not exercise Phase 2");
		return 1;
	}
	if (new_present_corrupt) {
		fail("%u surviving VMAs have corrupt data", new_present_corrupt);
		return 1;
	}

	test_msg("OK: stable intact, %u VMAs tracked (%u ok, %u missing)\n",
		 nr_tracked, new_present_ok, new_missing);
	pass();
	return 0;
}
