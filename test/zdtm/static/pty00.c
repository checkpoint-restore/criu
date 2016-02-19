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

const char *test_doc	= "Check, that pseudoterminals are restored";
const char *test_author	= "Andrey Vagin <avagin@openvz.org>";

static unsigned int nr_sighups;

static void signal_handler_sighup(int signum)
{
	nr_sighups++;
}

int main(int argc, char ** argv)
{
	int fdm, fds, ret, tty;
	char *slavename;
	char buf[10];
	const char teststr[] = "hello\n";

	struct sigaction sa = {
		.sa_handler = signal_handler_sighup,
		.sa_flags = 0,
	};

	test_init(argc, argv);

	/*
	 * On closing control terminal we're expecting to
	 * receive SIGHUP, so make sure it's delivered.
	 */
	if (sigaction(SIGHUP, &sa, 0)) {
		fail("sigaction failed\n");
		return 1;
	}

	fdm = open("/dev/ptmx", O_RDWR);
	if (fdm == -1) {
		pr_perror("open(%s) failed", "/dev/ptmx");
		return 1;
	}
	grantpt(fdm);
	unlockpt(fdm);
	slavename = ptsname(fdm);
	fds = open(slavename, O_RDWR);
	if (fds == -1) {
		pr_perror("open(%s) failed", slavename);
		return 1;
	}

	tty = open("/dev/tty", O_RDWR);
	if (tty < 0) {
		pr_perror("open(%s) failed", "/dev/tty");
		return 1;
	}

	/* Try to reproduce a deadlock */
	if (dup2(fdm, 101) != 101) {
		pr_perror("dup( , 101) failed");
		return 1;
	}
	close(fdm);
	fdm = 101;

	if (dup2(fds, 100) != 100) {
		pr_perror("dup( , 100) failed");
		return 1;
	}
	close(fds);
	fds = 100;

	test_daemon();

	test_waitsig();

	/* Check connectivity */
	ret = write(fdm, teststr, sizeof(teststr) - 1);
	if (ret != sizeof(teststr) - 1) {
		pr_perror("write(fdm) failed");
		return 1;
	}

	ret = read(fds, buf, sizeof(teststr) - 1);
	if (ret != sizeof(teststr) - 1) {
		pr_perror("read(fds) failed");
		return 1;
	}

	if (strncmp(teststr, buf, sizeof(teststr) - 1)) {
		fail("data mismatch");
		return 1;
	}

	ret = write(fdm, teststr, sizeof(teststr) - 1);
	if (ret != sizeof(teststr) - 1) {
		pr_perror("write(fdm) failed");
		return 1;
	}

	ret = read(tty, buf, sizeof(teststr) - 1);
	if (ret != sizeof(teststr) - 1) {
		pr_perror("read(tty) failed");
		return 1;
	}

	if (strncmp(teststr, buf, sizeof(teststr) - 1)) {
		fail("data mismatch");
		return 1;
	}

	if (nr_sighups != 0) {
		fail("Expected 0 SIGHUP before closing control terminal but got %d", nr_sighups);
		return 1;
	}

	close(fdm);
	close(fds);
	close(tty);

	if (nr_sighups != 1) {
		fail("Expected 1 SIGHUP after closing control terminal but got %d", nr_sighups);
		return 1;
	} else
		pass();

	return 0;
}
