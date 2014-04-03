#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include "zdtmtst.h"

const char *test_doc	= "Test for huge VMA area";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

int main(int argc, char **argv)
{
	test_init(argc, argv);
	unsigned char *mem;

	test_msg("Alloc huge VMA\n");
	mem = (void *)mmap(NULL, (10L << 30), PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if ((void *)mem == MAP_FAILED) {
		err("mmap failed: %m");
		return -1;
	}

	mem[4L << 30] = 1;
	mem[8L << 30] = 2;

	test_daemon();
	test_waitsig();

	test_msg("Testing restored data\n");

	if (mem[4L << 30] != 1 || mem[8L << 30] != 2) {
		fail("Data corrupted!\n");
		exit(1);
	}

	pass();

	return 0;
}
