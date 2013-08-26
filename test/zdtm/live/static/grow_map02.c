#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that a few grow-down VMA-s are restored correctly";
const char *test_author	= "Andrew Vagin <avagin@openvz.org>";

int main(int argc, char **argv)
{
	char *start_addr, *grow_down;
	test_init(argc, argv);

	start_addr = mmap(NULL, PAGE_SIZE * 10, PROT_READ | PROT_WRITE,
					MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (start_addr == MAP_FAILED) {
		err("Can't mal a new region");
		return 1;
	}
	munmap(start_addr, PAGE_SIZE * 10);

	grow_down = mmap(start_addr + PAGE_SIZE * 3, PAGE_SIZE * 3,
			 PROT_READ | PROT_WRITE,
			 MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED | MAP_GROWSDOWN, -1, 0);
	if (grow_down == MAP_FAILED) {
		err("Can't mal a new region");
		return 1;
	}

	grow_down[0 * PAGE_SIZE] = 'x';
	grow_down[1 * PAGE_SIZE] = 'y';
	grow_down[2 * PAGE_SIZE] = 'z';

	/*
	 * Split the grow-down vma on three parts.
	 * Only the irst one will have a guard page
	 */
	if (mprotect(grow_down + PAGE_SIZE, PAGE_SIZE, PROT_READ)) {
		err("Can't change set protection on a region of memory");
		return 1;
	}

	test_daemon();
	test_waitsig();

	test_msg("%c %c %c\n", grow_down[0 * PAGE_SIZE],
		 grow_down[1 * PAGE_SIZE], grow_down[2 * PAGE_SIZE]);

	if (grow_down[0 * PAGE_SIZE] != 'x')
		return 1;
	if (grow_down[1 * PAGE_SIZE] != 'y')
		return 1;
	if (grow_down[2 * PAGE_SIZE] != 'z')
		return 1;

	pass();

	return 0;
}
