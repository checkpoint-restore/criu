#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include <string.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc	= "Sanity check for criu lock-test quirk";
const char *test_author	= "Pavel Emelyanov <xemul@parallels.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

int main(int argc, char **argv)
{
	int fd, fd2;

	test_init(argc, argv);

	fd = open(filename, O_CREAT | O_RDWR, 0600);
	if (fd < 0) {
		err("No file");
		return -1;
	}

	fd2 = open(filename, O_RDWR);
	if (fd2 < 0) {
		err("No file2");
		return -1;
	}

	flock(fd, LOCK_SH);

	test_daemon();
	test_waitsig();

	if (flock(fd2, LOCK_SH) == 0)
		pass();
	else
		fail("Flock file locks check failed");

	close(fd);
	close(fd2);
	unlink(filename);

	return 0;
}
