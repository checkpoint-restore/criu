#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>

#include "zdtmtst.h"

const char *test_doc	= "Check changing memory";
const char *test_author	= "Pavel Emelyanov <xemul@parallels.com>";

#define MEM_PAGES	16

int main(int argc, char **argv)
{
	void *mem;
	int i, fail = 0;
	unsigned rover = 1;
	unsigned backup[MEM_PAGES] = {};

	srand(time(NULL));

	test_init(argc, argv);

	mem = mmap(NULL, MEM_PAGES * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, 0, 0);
	if (mem == MAP_FAILED)
		return 1;

	test_msg("mem %p backup %p\n", mem, backup);

	test_daemon();
	while (test_go()) {
		unsigned pfn;

		pfn = random() % MEM_PAGES;
		*(unsigned *)(mem + pfn * PAGE_SIZE) = rover;
		backup[pfn] = rover;
		test_msg("t %u %u\n", pfn, rover);
		rover++;
		sleep(1);
	}
	test_waitsig();

	test_msg("final rover %u\n", rover);
	for (i = 0; i < MEM_PAGES; i++)
		if (backup[i] != *(unsigned *)(mem + i * PAGE_SIZE)) {
			test_msg("Page %u differs want %u has %u\n", i,
					backup[i], *(unsigned *)(mem + i * PAGE_SIZE));
			fail = 1;
		} else
			test_msg("Page %u matches %u\n", i, backup[i]);

	if (fail)
		fail("Memory corruption\n");
	else
		pass();

	return 0;
}

