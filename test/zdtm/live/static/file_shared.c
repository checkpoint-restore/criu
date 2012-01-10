#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>

#include "zdtmtst.h"
#define OFFSET 1000

const char *test_doc	= "Check shared struct file-s";
const char *test_author	= "Andrey Vagin <xemul@parallels.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

int main(int argc, char **argv)
{
	pid_t pid;
	int fd, ret, status;
	off_t off;

	test_init(argc, argv);

	fd = open(filename, O_RDWR | O_CREAT);
	if (fd == -1)
		return 1;

	fd = dup(fd);
	if (fd < 0)
		return 1;

	test_daemon();

	pid = test_fork();

	if (pid == -1)
		return 1;
	else if (pid) {
		test_waitsig();
		off = lseek(fd, OFFSET, SEEK_SET);
		if (off == (off_t) -1)
			return 1;

		ret = kill(pid, SIGTERM);
		if (ret == -1) {
			err("kill() failed: %m");
		}

		ret = wait(&status);
		if (ret == -1) {
			err("wait() failed: %m");
			return 1;
		}

		if (!WIFEXITED(status) || WEXITSTATUS(status)) {
			fail("Child exited with non-zero status");
			return 1;
		}
	} else {
		test_waitsig();
		off = lseek(fd, 0, SEEK_CUR);
		if (off != OFFSET) {
			fail("offset should be %d insted of %d\n");
			return 1;
		}
		return 0;
	}

	pass();

	return 0;
}
