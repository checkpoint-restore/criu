#define _GNU_SOURCE
#include <unistd.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <utime.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include <time.h>

#include "zdtmtst.h"

const char *test_doc	= "Test for fifo ro/wo with "
			  "fake fifo needed on crtools side";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

char *name_master;
TEST_OPTION(name_master, string, "master fifo name", 1);

char *name_slave;
TEST_OPTION(name_slave, string, "slave fifo name", 1);

#define TEST_VALUE	(00100)

#define exit_shot(pid, code)	\
	do { kill(pid, SIGKILL); exit(code); } while (0)

#define exit_shot_parent(code)	\
	exit_shot(getppid(), 1)

int main(int argc, char **argv)
{
	task_waiter_t t;
	pid_t pid;
	int fd_master, fd_slave;
	int v, status;

	test_init(argc, argv);

	if (mknod(name_master, S_IFIFO | 0700, 0)) {
		err("can't make fifo \"%s\": %m\n", name_master);
		exit(1);
	}

	if (mknod(name_slave, S_IFIFO | 0700, 0)) {
		err("can't make fifo \"%s\": %m\n", name_slave);
		exit(1);
	}

	fd_slave = open(name_slave, O_RDWR);
	if (fd_slave < 0) {
		err("can't open %s: %m\n", name_slave);
		exit(1);
	}

	task_waiter_init(&t);

	pid = test_fork();
	if (pid == 0) {
		int new_slave;

		fd_master = open(name_master, O_WRONLY);
		if (fd_master < 0) {
			err("can't open %s: %m\n", name_master);
			exit_shot_parent(1);
		}

		new_slave = dup2(fd_slave, 64);
		if (new_slave < 0) {
			err("can't dup %s: %m\n", name_slave);
			exit_shot_parent(1);
		}

		close(fd_slave);

		task_waiter_complete_current(&t);

		v = TEST_VALUE;
		if (write(new_slave, &v, sizeof(v)) != sizeof(v)) {
			err("write failed: %m\n");
			exit_shot_parent(1);
		}

		v = TEST_VALUE;
		if (write(fd_master, &v, sizeof(v)) != sizeof(v)) {
			err("write failed: %m\n");
			exit_shot_parent(1);
		}

		/* Don't exit until explicitly asked */
		task_waiter_wait4(&t, getppid());

		exit(0);
	} else if (pid < 0) {
		err("test_fork failed: %m\n");
		exit(1);
	}

	fd_master = open(name_master, O_RDONLY);
	if (fd_master < 0) {
		err("can't open %s: %m\n", name_master);
		exit_shot(pid, 1);
	}

	/* Wait until data appear in kernel fifo buffer */
	task_waiter_wait4(&t, pid);

	test_daemon();
	test_waitsig();

	if (read(fd_master, &v, sizeof(v)) != sizeof(v)) {
		err("read failed: %m\n");
		exit_shot(pid, 1);
	}

	task_waiter_complete_current(&t);

	if (v != TEST_VALUE) {
		fail("read data mismatch\n");
		exit_shot(pid, 1);
	}

	if (read(fd_slave, &v, sizeof(v)) != sizeof(v)) {
		err("read failed: %m\n");
		exit_shot(pid, 1);
	}
	if (v != TEST_VALUE) {
		fail("read data mismatch\n");
		exit_shot(pid, 1);
	}

	waitpid(pid, &status, P_ALL);

	if (unlink(name_master) < 0)
		err("can't unlink %s: %m", name_master);

	if (unlink(name_slave) < 0)
		err("can't unlink %s: %m", name_slave);

	if (!WIFEXITED(status)) {
		err("child %d is still running\n", pid);
		exit_shot(pid, 1);
	}

	errno = WEXITSTATUS(status);
	if (errno) {
		fail("Child exited with error %m");
		exit(errno);
	}

	pass();
	return 0;
}
