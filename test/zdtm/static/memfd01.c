#include <fcntl.h>
#include <linux/memfd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc	= "memfd with different file pointer";
const char *test_author	= "Nicolas Viennot <Nicolas.Viennot@twosigma.com>";

#define err(exitcode, msg, ...) ({ pr_perror(msg, ##__VA_ARGS__); exit(exitcode); })

static int _memfd_create(const char *name, unsigned int flags)
{
	return syscall(SYS_memfd_create, name, flags);
}

int main(int argc, char *argv[])
{
	pid_t pid, pid_child;
	int fd, ret, status;
	task_waiter_t t;

	test_init(argc, argv);

	task_waiter_init(&t);

	fd = _memfd_create("somename", MFD_CLOEXEC);
	if (fd < 0)
		err(1, "Can't call memfd_create");

	pid = getpid();

	pid_child = fork();
	if (pid_child < 0)
		err(1, "Can't fork");

	if (!pid_child) {
		char fdpath[100];
		char buf[1];
		int fl_flags1, fl_flags2, fd_flags1, fd_flags2;

		snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd/%d", pid, fd);
		/*
		 * We pass O_LARGEFILE because in compat mode, our file
		 * descriptor does not get O_LARGEFILE automatically, but the
		 * restorer using non-compat open() is forced O_LARGEFILE.
		 * This creates a flag difference, which we don't want to deal
		 * with this at the moment.
		 */
		fd = open(fdpath, O_RDONLY | O_LARGEFILE);
		if (fd < 0)
			err(1, "Can't open memfd via proc");

		if ((fl_flags1 = fcntl(fd, F_GETFL)) == -1)
			err(1, "Can't get fl flags");

		if ((fd_flags1 = fcntl(fd, F_GETFD)) == -1)
			err(1, "Can't get fd flags");

		task_waiter_complete(&t, 1);
		// checkpoint-restore happens here
		task_waiter_wait4(&t, 2);

		if (read(fd, buf, 1) != 1)
			err(1, "Can't read");

		if ((fl_flags2 = fcntl(fd, F_GETFL)) == -1)
			err(1, "Can't get fl flags");

		if (fl_flags1 != fl_flags2)
			err(1, "fl flags differs");

		if ((fd_flags2 = fcntl(fd, F_GETFD)) == -1)
			err(1, "Can't get fd flags");

		if (fd_flags1 != fd_flags2)
			err(1, "fd flags differs");

		if (buf[0] != 'x')
			err(1, "Read incorrect");

		return 0;
	}

	task_waiter_wait4(&t, 1);

	test_daemon();
	test_waitsig();

	if (write(fd, "x", 1) != 1)
		err(1, "Can't write");

	task_waiter_complete(&t, 2);

	ret = wait(&status);
	if (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status)) {
		kill(pid, SIGKILL);
		fail("child had issue");
		return 1;
	}

	pass();

	return 0;
}
