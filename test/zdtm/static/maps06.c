#include "zdtmtst.h"
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

const char *test_doc	= "Create a lot of file vma-s";
const char *test_author	= "Andrei Vagin <avagin@openvz.org>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

int main(int argc, char ** argv)
{
	int fd, i;

	test_init(argc, argv);

	fd = open(filename, O_RDWR | O_CREAT, 0666);
	if (fd < 0)
		return 1;

	ftruncate(fd, 4096);

	for (i = 0; i < 1024; i++) {
		if (mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FILE, fd, 0) == MAP_FAILED)
			return 1;
		if (mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED)
			return 1;
	}

	test_daemon();

	test_waitsig();

	pass();

	return 0;
}
