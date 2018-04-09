#include "zdtmtst.h"
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

const char *test_doc	= "Create a lot of file vma-s";
const char *test_author	= "Andrei Vagin <avagin@openvz.org>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

#define TEST_SIZE 10240

int main(int argc, char ** argv)
{
	void *start;
	int fd, i;

	test_init(argc, argv);

	fd = open(filename, O_RDWR | O_CREAT, 0666);
	if (fd < 0)
		return 1;

	ftruncate(fd, 4096);

	start = mmap(0, 4096 * TEST_SIZE * 4, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (start == MAP_FAILED)
		return 1;

	for (i = 0; i < TEST_SIZE; i++) {
		int *addr;
		addr = mmap(start + i * 3 * 4096, 4096,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_FILE | MAP_FIXED, fd, 0);
		if (addr == MAP_FAILED)
			return 1;
		addr[0] = i * 2;
		addr = mmap(start + (i * 3 + 1) * 4096, 4096,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		if (addr == MAP_FAILED)
			return 1;
		addr[0] = i;
	}

	test_daemon();

	test_waitsig();

	for (i = 0; i < TEST_SIZE; i++) {
		int *addr;
		addr = start + i * 3 * 4096;
		if (addr[0] != i * 2)
			fail();
		addr = start + (i * 3  + 1) * 4096;
		if (addr[0] != i)
			fail();
	}

	pass();

	return 0;
}
