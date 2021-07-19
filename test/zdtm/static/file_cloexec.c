#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check FD_CLOEXEC flag";
const char *test_author = "Nicolas Viennot <Nicolas.Viennot@twosigma.com>";

#define err(exitcode, msg, ...)                \
	({                                     \
		pr_perror(msg, ##__VA_ARGS__); \
		exit(exitcode);                \
	})

static void assert_fd_flags(int fd, int mask, int value)
{
	int flags = fcntl(fd, F_GETFD);
	if (flags == -1)
		err(1, "Can't get fd flags");

	if ((flags & mask) != value) {
		fail("fd flags mismatch");
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	int fd1, fd2, fd3, fd4;

	test_init(argc, argv);

	fd1 = open("/", O_RDONLY | O_CLOEXEC);
	if (fd1 < 0)
		err(1, "Can't open()");

	fd2 = open("/", O_RDONLY);
	if (fd2 < 0)
		err(1, "Can't open()");

	fd3 = dup(fd1);
	if (fd3 < 0)
		err(1, "Can't dup()");

	fd4 = fcntl(fd2, F_DUPFD_CLOEXEC, 0);
	if (fd4 < 0)
		err(1, "Can't dup()");

	test_daemon();
	test_waitsig();

	assert_fd_flags(fd1, FD_CLOEXEC, FD_CLOEXEC);
	assert_fd_flags(fd2, FD_CLOEXEC, 0);
	assert_fd_flags(fd3, FD_CLOEXEC, 0);
	assert_fd_flags(fd4, FD_CLOEXEC, FD_CLOEXEC);

	pass();

	return 0;
}
