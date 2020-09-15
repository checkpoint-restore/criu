#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc	= "File validation test for checksum (checksum-first) with checksum parameter and file size equal to 10485800 (Should fail during restore)";
const char *test_author	= "Ajay Bharadwaj <ajayrbharadwaj@gmail.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

#define BUF_SIZE 10485800

int main(int argc, char **argv)
{
	int fd;
	void *buf;
	uint32_t crc;

	test_init(argc, argv);

	fd = open(filename, O_RDWR | O_CREAT, 0666);
	if (fd < 0) {
		pr_perror("Can't open %s", filename);
		return 1;
	}

	buf = mmap(NULL, BUF_SIZE, PROT_WRITE | PROT_READ,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED) {
		pr_perror("mmap() failed");
		return 1;
	}

	crc = ~0;
	datagen(buf, BUF_SIZE, &crc);
	if (write_data(fd, buf, BUF_SIZE)) {
		pr_perror("write() failed");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (close(fd) < 0) {
		pr_perror("Can't close %s", filename);
		return 1;
	}

	fail("Restore passed even though file was altered\n");
	return 0;
}