#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that VMA-s with MAP_GROWSDOWN are restored correctly";
const char *test_author	= "Andrew Vagin <avagin@openvz.org>";

/*
* This test case creates two consecutive grows down vmas with a hole
* between them.
*/

int main(int argc, char **argv)
{
	char *start_addr, *addr1, *addr2;

	test_init(argc, argv);

	start_addr = mmap(NULL, PAGE_SIZE * 10, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (start_addr == MAP_FAILED) {
		err("Can't mal a new region");
		return 1;
	}
	munmap(start_addr, PAGE_SIZE * 10);

	addr1 = mmap(start_addr + PAGE_SIZE * 5, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_GROWSDOWN, -1, 0);
	addr2 = mmap(start_addr + PAGE_SIZE * 3, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_GROWSDOWN, -1, 0);

	test_msg("%p %p\n", addr1, addr2);

	test_daemon();
	test_waitsig();

	pass();

	return 0;
}
