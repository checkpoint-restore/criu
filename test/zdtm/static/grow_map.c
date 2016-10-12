#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that VMA-s with MAP_GROWSDOWN are restored correctly";
const char *test_author	= "Andrew Vagin <avagin@openvz.org>";

int main(int argc, char **argv)
{
	char *start_addr, *fake_grow_down, *test_addr, *grow_down;
	volatile char *p;
	test_init(argc, argv);

	start_addr = mmap(NULL, PAGE_SIZE * 10, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (start_addr == MAP_FAILED) {
		pr_perror("Can't mal a new region");
		return 1;
	}
	munmap(start_addr, PAGE_SIZE * 10);

	fake_grow_down = mmap(start_addr + PAGE_SIZE * 5, PAGE_SIZE,
			 PROT_READ | PROT_WRITE,
			 MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED | MAP_GROWSDOWN, -1, 0);
	if (fake_grow_down == MAP_FAILED) {
		pr_perror("Can't mal a new region");
		return 1;
	}

	p = fake_grow_down;
	*p-- = 'c';
	*p = 'b';

	/* overlap the guard page of fake_grow_down */
	test_addr = mmap(start_addr + PAGE_SIZE * 3, PAGE_SIZE,
			 PROT_READ | PROT_WRITE,
			 MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
	if (test_addr == MAP_FAILED) {
		pr_perror("Can't mal a new region");
		return 1;
	}

	grow_down = mmap(start_addr + PAGE_SIZE * 2, PAGE_SIZE,
			 PROT_READ | PROT_WRITE,
			 MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED | MAP_GROWSDOWN, -1, 0);
	if (grow_down == MAP_FAILED) {
		pr_perror("Can't mal a new region");
		return 1;
	}

	test_daemon();
	test_waitsig();

	munmap(test_addr, PAGE_SIZE);
	if (fake_grow_down[0] != 'c' || *(fake_grow_down - 1) != 'b') {
		fail("%c %c\n", fake_grow_down[0], *(fake_grow_down - 1));
		return 1;
	}

	p = grow_down;
	*p-- = 'z';
	*p = 'x';

	pass();

	return 0;
}
