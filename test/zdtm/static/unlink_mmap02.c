#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>

#include "zdtmtst.h"

const char *test_doc = "Test mmapped, opened and unlinked files";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

static void touch_file_page(int fd, unsigned long off, char c)
{
	if (lseek(fd, off, SEEK_SET) != off) {
		pr_perror("Lseek fail");
		exit(1);
	}

	if (write(fd, &c, 1) != 1) {
		pr_perror("Write fail");
		exit(1);
	}
}

int main(int argc, char **argv)
{
	int fd;
	char *mem_a, *mem_b;

	test_init(argc, argv);

	fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("can't open file");
		exit(1);
	}

	touch_file_page(fd, 2 * PAGE_SIZE - 1, 'c'); /* for aligned file */

	/* map with different prots to create 2 regions */
	mem_a = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE | MAP_FILE, fd, 0);
	mem_b = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FILE, fd, PAGE_SIZE);
	if (mem_a == MAP_FAILED || mem_b == MAP_FAILED) {
		pr_perror("can't map file");
		exit(1);
	}

	if (unlink(filename) < 0) {
		pr_perror("can't unlink file");
		exit(1);
	}

	test_daemon();
	test_waitsig();

	touch_file_page(fd, 0, 'a');
	touch_file_page(fd, PAGE_SIZE, 'b');

	if (mem_a[0] != 'a')
		fail("1st region fail");
	else if (mem_b[0] != 'b' || mem_b[PAGE_SIZE - 1] != 'c')
		fail("2nd regin fail");
	else
		pass();

	return 0;
}
