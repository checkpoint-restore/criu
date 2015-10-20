#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "zdtmtst.h"

const char *test_doc	= "Check c/r of a virtual terminal";
const char *test_author	= "Ruslan Kuprieiev <kupruser@gmail.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

int main(int argc, char **argv)
{
	struct stat st1, st2;
	int fd;

	test_init(argc, argv);

	if (mknod(filename, S_IFCHR | S_IRUSR | S_IWUSR, makedev(4, 5))) {
		pr_perror("Can't create virtual terminal %s", filename);
		return 1;
	}

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		pr_perror("Open virtual terminal %s failed", filename);
		return 1;
	}

	if (fstat(fd, &st1)) {
		pr_perror("Can't stat %s virtual terminal", filename);
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (fstat(fd, &st2)) {
		pr_perror("Can't stat %s virtual terminal", filename);
		return 1;
	}

	if (st1.st_rdev != st2.st_rdev) {
		fail("Virtual terminal rdev mismatch %x != %x on %s",
		     (int)st1.st_rdev, (int)st2.st_rdev,
		     filename);
		return 1;
	}

	pass();
	return 0;
}
