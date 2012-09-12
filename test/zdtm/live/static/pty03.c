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
#include <sys/ioctl.h>

const char *test_doc	= "Check a non-opened control terminal";
const char *test_author	= "Andrey Vagin <avagin@openvz.org>";

static const char teststr[] = "ping\n";

int main(int argc, char *argv[])
{
	char buf[sizeof(teststr)];
	int master, slave, ret;
	char *slavename;

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

	if (ioctl(slave, TIOCSCTTY, 1)) {
		err("Can't set a controll terminal");
		return 1;
	}

	close(slave);

	test_daemon();
	test_waitsig();

	slave = open("/dev/tty", O_RDWR);
	if (slave == -1) {
		err("Can't open the controll terminal");
		return -1;
	}

	signal(SIGHUP, SIG_IGN);

	ret = write(master, teststr, sizeof(teststr) - 1);
	if (ret != sizeof(teststr) - 1) {
		err("write(master) failed");
		return 1;
	}

	ret = read(slave, buf, sizeof(teststr) - 1);
	if (ret != sizeof(teststr) - 1) {
		err("read(slave1) failed");
		return 1;
	}

	if (strncmp(teststr, buf, sizeof(teststr) - 1)) {
		fail("data mismatch");
		return 1;
	}

	close(master);
	close(slave);

	pass();

	return 0;
}
