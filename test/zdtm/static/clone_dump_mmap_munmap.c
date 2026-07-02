#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "zdtmtst.h"
#include "clone_dump_util.h"

const char *test_doc = "--clone-dump with background mmap/munmap cycles. "
		       "Tests UFFD REMOVE events and Phase 3 new-VMA detection. "
		       "Stable region must survive byte-exact with tracked state.";
const char *test_author = "Asaf Porat Stoler <asafpor@gmail.com>";


#define STABLE_PAGES	512
#define CYCLE_PAGES	16
#define DRAIN_TIMEOUT	10000

static atomic_int stop_mapper;
static atomic_size_t mmap_cycles;
static atomic_size_t munmap_cycles;

static inline unsigned char page_marker(int page_idx, int byte_offset)
{
	return (unsigned char)((page_idx * 7 + byte_offset) & 0xff);
}

static void *mapper_thread(void *arg)
{
	while (!atomic_load(&stop_mapper)) {
		unsigned char *p;
		p = mmap(NULL, CYCLE_PAGES * PAGE_SIZE,
			 PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p == MAP_FAILED)
			continue;
		atomic_fetch_add(&mmap_cycles, 1);
		memset(p, 0x5a, CYCLE_PAGES * PAGE_SIZE);
		munmap(p, CYCLE_PAGES * PAGE_SIZE);
		atomic_fetch_add(&munmap_cycles, 1);
	}
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t th;
	unsigned char *stable;
	unsigned long sz = STABLE_PAGES * PAGE_SIZE;
	int i, j;
	int errors = 0;
	int first_error = -1, last_error = -1;
	size_t snap_mmap, snap_munmap;

	test_init(argc, argv);

	stable = mmap(NULL, sz, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (stable == MAP_FAILED) {
		pr_perror("mmap stable");
		return 1;
	}

	for (i = 0; i < STABLE_PAGES; i++) {
		unsigned char *page = stable + i * PAGE_SIZE;
		for (j = 0; j < PAGE_SIZE; j++)
			page[j] = page_marker(i, j);
	}

	atomic_init(&stop_mapper, 0);
	atomic_init(&mmap_cycles, 0);
	atomic_init(&munmap_cycles, 0);

	if (pthread_create(&th, NULL, mapper_thread, NULL)) {
		pr_perror("pthread_create");
		return 1;
	}

	test_daemon();
	test_waitsig();

	snap_mmap = atomic_load(&mmap_cycles);
	snap_munmap = atomic_load(&munmap_cycles);

	atomic_store(&stop_mapper, 1);
	pthread_join(th, NULL);

	test_msg("State at restore: mmap_cycles=%zu munmap_cycles=%zu\n",
		 snap_mmap, snap_munmap);

	if (clone_wait_for_drain(stable, sz, DRAIN_TIMEOUT) < 0) {
		fail("stable region drain did not complete within %d ms", DRAIN_TIMEOUT);
		return 1;
	}

	for (i = 0; i < STABLE_PAGES; i++) {
		unsigned char *page = stable + i * PAGE_SIZE;
		int page_ok = 1;

		for (j = 0; j < PAGE_SIZE; j++) {
			unsigned char expected = page_marker(i, j);
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
		test_msg("SUMMARY: %d/%d pages corrupted, "
			 "first=%d last=%d, cycles=%zu/%zu\n",
			 errors, STABLE_PAGES, first_error, last_error,
			 snap_mmap, snap_munmap);
		fail("stable pages corrupted after --clone-dump restore");
		return 1;
	}

	test_msg("OK: all %d stable pages verified, %zu mmap/munmap cycles\n",
		 STABLE_PAGES, snap_mmap);
	pass();
	return 0;
}
