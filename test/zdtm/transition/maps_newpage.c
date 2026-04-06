#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "zdtmtst.h"

const char *test_doc = "Test pages with cleared soft-dirty after pre-dump";
const char *test_author = "Radostin Stoyanov <rstoyanov@fedoraproject.org>";

/*
 * After a pre-dump, soft-dirty bits are cleared. If new pages are
 * then written and soft-dirty is cleared again (e.g. by a device
 * driver or by writing to /proc/self/clear_refs), CRIU sees
 * "present, not dirty" and classifies them as PE_PARENT. But the
 * parent has no data for these pages, causing restore to fail with
 * "Hole not found in parent".
 *
 * This test simulates the scenario by:
 * 1. Mapping and writing init pages (will be in pre-dump)
 * 2. Letting the pre-dump run
 * 3. Mapping new pages in a separate VMA and writing a pattern
 * 4. Clearing soft-dirty via /proc/self/clear_refs
 * 5. Re-dirtying init pages so they are dumped normally
 * 6. Letting the final dump run — the new pages appear "clean"
 *    but have no parent data
 */

#define INIT_PAGES	4
#define NEW_PAGES	4

static int clear_soft_dirty(void)
{
	int fd;
	ssize_t ret;

	fd = open("/proc/self/clear_refs", O_WRONLY);
	if (fd < 0) {
		pr_perror("open clear_refs");
		return -1;
	}
	/* 4 = clear soft-dirty bits */
	ret = write(fd, "4", 1);
	close(fd);
	if (ret != 1) {
		pr_perror("write clear_refs");
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	unsigned char *init_mem, *new_mem = NULL;
	size_t init_size = INIT_PAGES * PAGE_SIZE;
	size_t new_size = NEW_PAGES * PAGE_SIZE;
	int i;

	test_init(argc, argv);

	/* Map and write init pages — these go into the pre-dump */
	init_mem = mmap(NULL, init_size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (init_mem == MAP_FAILED) {
		pr_perror("mmap init");
		return 1;
	}
	memset(init_mem, 0xAB, init_size);

	test_daemon();

	/* Wait for pre-dump to complete */
	if (test_wait_pre_dump())
		goto skip;

	/*
	 * Map new pages in a separate VMA and write a pattern.
	 * This creates real page backing (not the kernel zero page).
	 */
	new_mem = mmap(NULL, new_size, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (new_mem == MAP_FAILED) {
		pr_perror("mmap new");
		test_wait_pre_dump_ack();
		return 1;
	}
	memset(new_mem, 0xCD, new_size);

	/*
	 * Clear soft-dirty for all pages. Now CRIU sees the new
	 * pages as "present, not dirty" → PE_PARENT, but the
	 * parent has no data for them.
	 */
	if (clear_soft_dirty()) {
		test_wait_pre_dump_ack();
		return 1;
	}

	/*
	 * Re-dirty init pages so CRIU dumps them as PE_PRESENT.
	 * Without this, they would also go to PE_PARENT (which
	 * would work since the parent has them, but let's keep
	 * the test focused on the new pages).
	 */
	memset(init_mem, 0xAB, init_size);

	test_wait_pre_dump_ack();

skip:
	test_waitsig();

	/* Verify init pages kept their pattern */
	for (i = 0; i < (int)init_size; i++) {
		if (init_mem[i] != 0xAB) {
			fail("init_mem[%d] = 0x%02x, expected 0xAB",
			     i, init_mem[i]);
			return 1;
		}
	}

	/*
	 * The new pages will be zero after restore: CRIU thought
	 * they were in the parent, so the fix writes zero pages.
	 * The 0xCD data is lost, but the process doesn't crash.
	 */
	if (new_mem) {
		for (i = 0; i < (int)new_size; i++) {
			if (new_mem[i] != 0x00) {
				fail("new_mem[%d] = 0x%02x, expected 0x00",
				     i, new_mem[i]);
				return 1;
			}
		}
	}

	pass();
	return 0;
}
