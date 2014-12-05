#define _XOPEN_SOURCE
#include <stdlib.h>
#include "zdtmtst.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <signal.h>

const char *test_doc	= "Check forked master ptmx";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

static const char teststr[] = "ping\n";

#define exit_shot(pid, code)	\
	do { kill(pid, SIGKILL); exit(code); } while (0)

#define exit_shot_parent(code)	\
	exit_shot(getppid(), 1)

int main(int argc, char *argv[])
{
	char buf[sizeof(teststr)];
	int master, slave, ret;
	char *slavename;
	task_waiter_t t;
	pid_t pid;

	test_init(argc, argv);

	master = open("/dev/ptmx", O_RDWR);
	if (master == -1) {
		err("open(%s) failed", "/dev/ptmx");
		return 1;
	}

	grantpt(master);
	unlockpt(master);

	slavename = ptsname(master);
	slave = open(slavename, O_RDWR);
	if (slave == -1) {
		err("open(%s) failed", slavename);
		return 1;
	}

	task_waiter_init(&t);

	pid = test_fork();
	if (pid == 0) {
		int new_master, ret;

		new_master = dup(master);
		if (new_master < 0) {
			err("can't dup master\n");
			exit_shot_parent(1);
		}

		task_waiter_complete_current(&t);

		ret = write(new_master, teststr, sizeof(teststr) - 1);
		if (ret != sizeof(teststr) - 1) {
			err("write(new_master) failed (ret = %d)", ret);
			exit_shot_parent(1);
		}

		task_waiter_wait4(&t, 1);

		close(new_master);
		exit(0);
	} else if (pid < 0) {
		err("test_fork failed: %m\n");
		exit(1);
	}

	task_waiter_wait4(&t, pid);
	close(master);

	test_daemon();
	test_waitsig();

	signal(SIGHUP, SIG_IGN);

	ret = read(slave, buf, sizeof(teststr) - 1);
	if (ret != sizeof(teststr) - 1) {
		err("read(slave) failed (ret = %d)", ret);
		return 1;
	}

	if (strncmp(teststr, buf, sizeof(teststr) - 1)) {
		fail("data mismatch");
		return 1;
	}

	task_waiter_complete(&t, 1);
	close(slave);

	pass();

	return 0;
}
