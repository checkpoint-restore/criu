#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "zdtmtst.h"

const char *test_doc = "Check sparse incremental restore across region boundaries";
const char *test_author = "Radostin Stoyanov <rstoyanov@fedoraproject.org>";

#define MEM_SIZE	(64UL << 20)
#define REGION_SIZE	(1UL << 20)
#define INITIAL_BYTE	0x11
#define PARENT_BYTE	0x22
#define FINAL_BYTE	0x33

static void fill_pages(char *mapping, unsigned char value, unsigned int step)
{
	size_t page;

	for (page = 0; page < MEM_SIZE / PAGE_SIZE; page += step)
		memset(mapping + page * PAGE_SIZE, value, PAGE_SIZE);
}

static void update_parent_pattern(char *mapping)
{
	/*
	 * Queue intermediate region 0, queue grandparent region 1, then force a
	 * partial grandparent read with the inherited tail of region 2. Region 3
	 * remains available for the final image to request partially.
	 */
	memset(mapping, PARENT_BYTE, REGION_SIZE);
	memset(mapping + 2 * REGION_SIZE, PARENT_BYTE, PAGE_SIZE);
	memset(mapping + 3 * REGION_SIZE, PARENT_BYTE, REGION_SIZE);
}

static void update_final_pattern(char *mapping)
{
	/*
	 * The final image owns one page of intermediate region 3. Restoring its
	 * inherited tail first flushes encoded work queued in both parent readers.
	 * Without one context for the complete chain, those readers retain both
	 * batch permits and the final reader deadlocks acquiring a third.
	 */
	memset(mapping + 3 * REGION_SIZE, FINAL_BYTE, PAGE_SIZE);
}

static int verify_pages(const char *mapping, unsigned int generation)
{
	size_t page;

	for (page = 0; page < MEM_SIZE / PAGE_SIZE; page++) {
		bool in_parent_region = page < REGION_SIZE / PAGE_SIZE ||
			page == 2 * REGION_SIZE / PAGE_SIZE ||
			(page >= 3 * REGION_SIZE / PAGE_SIZE &&
			 page < 4 * REGION_SIZE / PAGE_SIZE);
		unsigned char value = generation && in_parent_region ?
			PARENT_BYTE : INITIAL_BYTE;
		size_t byte;

		if (generation > 1 && page == 3 * REGION_SIZE / PAGE_SIZE)
			value = FINAL_BYTE;

		for (byte = 0; byte < PAGE_SIZE; byte++) {
			unsigned char actual = mapping[page * PAGE_SIZE + byte];

			if (actual != value) {
				fail("page %zu byte %zu is %#x, expected %#x",
				     page, byte, actual, value);
				return -1;
			}
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	char *mapping;
	unsigned int generation = 0;

	test_init(argc, argv);

	mapping = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mapping == MAP_FAILED) {
		pr_perror("mmap");
		return 1;
	}

	fill_pages(mapping, INITIAL_BYTE, 1);
	test_daemon();

	while (test_go()) {
		if (test_wait_pre_dump()) {
			if (test_go()) {
				fail("failed waiting for pre-dump notification");
				return 1;
			}
			break;
		}

		if (generation == 0)
			update_parent_pattern(mapping);
		else if (generation == 1)
			update_final_pattern(mapping);
		generation++;

		if (test_wait_pre_dump_ack()) {
			fail("failed acknowledging pre-dump notification");
			return 1;
		}
	}

	if (verify_pages(mapping, generation))
		return 1;

	pass();
	return 0;
}
