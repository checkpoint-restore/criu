#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc	= "File validation test for checksum (Should fail during restore, uses checksum-full)";
const char *test_author	= "Ajay Bharadwaj <ajayrbharadwaj@gmail.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

#define BUF_SIZE 1024

int main(int argc, char **argv)
{
	int fd;
	uint8_t buf[BUF_SIZE];
	uint32_t crc;

	test_init(argc, argv);

	fd = open(filename, O_RDWR | O_CREAT, 0666);
	if (fd < 0) {
		pr_perror("Can't open %s", filename);
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