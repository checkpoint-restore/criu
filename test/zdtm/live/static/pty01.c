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

const char *test_doc	= "Check two pts on ptmx";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

static const char teststr[] = "ping\n";

int main(int argc, char *argv[])
{
	char buf[sizeof(teststr)];
	int master, slave1, slave2, ret;
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
	slave1 = open(slavename, O_RDWR);
	if (slave1 == -1) {
		err("open(%s) failed", slavename);
		return 1;
	}

	slave2 = open(slavename, O_RDWR);
	if (slave2 == -1) {
		err("open(%s) failed", slavename);
		return 1;
	}

	test_daemon();
	test_waitsig();

	signal(SIGHUP, SIG_IGN);

	ret = write(master, teststr, sizeof(teststr) - 1);
	if (ret != sizeof(teststr) - 1) {
		err("write(master) failed");
		return 1;
	}

	ret = read(slave1, buf, sizeof(teststr) - 1);
	if (ret != sizeof(teststr) - 1) {
		err("read(slave1) failed");
		return 1;
	}

	if (strncmp(teststr, buf, sizeof(teststr) - 1)) {
		fail("data mismatch");
		return 1;
	}

	ret = write(master, teststr, sizeof(teststr) - 1);
	if (ret != sizeof(teststr) - 1) {
		err("write(master) failed");
		return 1;
	}

	ret = read(slave2, buf, sizeof(teststr) - 1);
	if (ret != sizeof(teststr) - 1) {
		err("read(slave1) failed");
		return 1;
	}

	if (strncmp(teststr, buf, sizeof(teststr) - 1)) {
		fail("data mismatch");
		return 1;
	}

	close(master);
	close(slave1);
	close(slave2);

	pass();

	return 0;
}
