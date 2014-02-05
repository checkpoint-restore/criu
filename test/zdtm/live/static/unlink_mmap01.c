#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>

#include "zdtmtst.h"

const char *test_doc	= "Test mmaped and unlinked files (2, with hard links)";

char *filename;
TEST_OPTION(filename, string, "file name", 1);
static char linkname[4096];

#ifndef PAGE_SIZE
#define PAGE_SIZE	4096
#endif

static void touch_file_page(int fd, unsigned long off, char c)
{
	if (lseek(fd, off, SEEK_SET) != off) {
		err("Lseek fail");
		exit(1);
	}

	if (write(fd, &c, 1) != 1) {
		err("Write fail");
		exit(1);
	}
}

int main(int argc, char ** argv)
{
	int fd;
	char *mem_a, *mem_b;

	test_init(argc, argv);

	fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		err("can't open file");
		exit(1);
	}

	touch_file_page(fd, 0, 'a');
	touch_file_page(fd, PAGE_SIZE - 1, 'b');/* for aligned file */

	mem_a = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE | MAP_FILE, fd, 0);
	if (mem_a == MAP_FAILED) {
		err("can't map file");
		exit(1);
	}

	sprintf(linkname, "%s.lnk", filename);
	if (link(filename, linkname)) {
		err("can't link file");
		exit(1);
	}

	if (unlink(filename) < 0) {
		err("can't unlink file");
		exit(1);
	}

	close(fd);

	fd = open(linkname, O_RDWR);
	if (fd < 0) {
		err("can't open link");
		exit(1);
	}

	mem_b = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE | MAP_FILE, fd, 0);
	if (mem_b == MAP_FAILED) {
		err("can't map link");
		exit(1);
	}

	if (unlink(linkname) < 0) {
		err("can't unlink link");
		exit(1);
	}

	close(fd);

	test_daemon();
	test_waitsig();

	if (mem_a[0] != 'a' || mem_a[PAGE_SIZE - 1] != 'b')
		fail("1st region fail");
	else if (mem_b[0] != 'a' || mem_b[PAGE_SIZE - 1] != 'b')
		fail("2nd regin fail");
	else
		pass();

	return 0;
}
