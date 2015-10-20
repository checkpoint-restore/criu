#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>

#include "zdtmtst.h"
#define OFFSET 1000
#define OFFSET2 500

const char *test_doc	= "Check shared struct file-s";
const char *test_author	= "Andrey Vagin <avagin@openvz.org>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

int main(int argc, char **argv)
{
	pid_t pid;
	int fd, fd2, fd3, ret, status;
	off_t off;

	test_init(argc, argv);

	fd = open(filename, O_RDWR | O_CREAT, 0644);
	if (fd == -1)
		return 1;

	fd2 = dup(fd);
	if (fd < 0)
		return 1;

	fd3 = open(filename, O_RDWR | O_CREAT, 0644);
	if (fd3 == -1)
		return 1;

	pid = test_fork();

	if (pid == -1)
		return 1;
	else if (pid) {
		fcntl(fd2, F_SETFD, 1);

		test_daemon();
		test_waitsig();
		off = lseek(fd, OFFSET, SEEK_SET);
		if (off == (off_t) -1)
			return 1;

		off = lseek(fd3, OFFSET2, SEEK_SET);
		if (off == (off_t) -1)
			return 1;

		ret = kill(pid, SIGTERM);
		if (ret == -1) {
			pr_perror("kill() failed");
		}

		ret = wait(&status);
		if (ret == -1) {
			pr_perror("wait() failed");
			return 1;
		}

		if (!WIFEXITED(status) || WEXITSTATUS(status)) {
			fail("Child exited with non-zero status");
			return 1;
		}
		off = lseek(fd2, 0, SEEK_CUR);
		if (off != OFFSET) {
			fail("offset1 fail\n");
			return 1;
		}
		off = lseek(fd3, 0, SEEK_CUR);
		if (off != OFFSET2) {
			fail("offset2 fail\n");
			return 1;
		}

		ret = fcntl(fd, F_GETFD, 0);
		if (ret != 0) {
			fail("fd cloexec broken\n");
			return 1;
		}

		ret = fcntl(fd2, F_GETFD, 0);
		if (ret != 1) {
			fail("fd2 cloexec broken\n");
			return 1;
		}

	} else {
		test_waitsig();
		off = lseek(fd, 0, SEEK_CUR);
		if (off != OFFSET) {
			fail("offset3 fail\n");
			return 1;
		}
		off = lseek(fd2, 0, SEEK_CUR);
		if (off != OFFSET) {
			fail("offset4 fail\n");
			return 1;
		}
		off = lseek(fd3, 0, SEEK_CUR);
		if (off != OFFSET2) {
			fail("offset5 fail\n");
			return 1;
		}
		return 0;
	}

	pass();

	return 0;
}
