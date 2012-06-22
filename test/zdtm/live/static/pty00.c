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

int main(int argc, char ** argv)
{
	int fdm, fds, ret;
	char *slavename;
	char buf[10];
	const char teststr[] = "hello\n";

	test_init(argc, argv);

	fdm = open("/dev/ptmx", O_RDWR);
	if (fdm == -1) {
		err("open(%s) failed", "/dev/ptmx");
		return 1;
	}
	grantpt(fdm);
	unlockpt(fdm);
	slavename = ptsname(fdm);
	fds = open(slavename, O_RDWR);
	if (fds == -1) {
		err("open(%s) failed", slavename);
		return 1;
	}

	/* Try to reproduce a deadlock */
	if (dup2(fdm, 101) != 101) {
		err("dup( , 101) failed");
		return 1;
	}
	close(fdm);
	fdm = 101;

	if (dup2(fds, 100) != 100) {
		err("dup( , 100) failed");
		return 1;
	}
	close(fds);
	fds = 100;

	test_daemon();

	test_waitsig();

	signal(SIGHUP, SIG_IGN);

	/* Check connectivity */
	ret = write(fdm, teststr, sizeof(teststr) - 1);
	if (ret != sizeof(teststr) - 1) {
		err("write(fdm) failed");
		return 1;
	}

	ret = read(fds, buf, sizeof(teststr) - 1);
	if (ret != sizeof(teststr) - 1) {
		err("read(fds) failed");
		return 1;
	}

	if (strncmp(teststr, buf, sizeof(teststr) - 1)) {
		fail("data mismatch");
		return 1;
	}

	close(fdm);
	close(fds);

	pass();

	return 0;
}
