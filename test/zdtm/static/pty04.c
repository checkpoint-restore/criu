#define _XOPEN_SOURCE 500
#include "zdtmtst.h"
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

const char *test_doc = "Check two pts with a fake ptmx";
const char *test_author = "Cyrill Gorcunov <gorcunov@openvz.org>";

int main(int argc, char *argv[])
{
	int master, slave1, slave2;
	char *slavename;

	test_init(argc, argv);

	master = open("/dev/ptmx", O_RDWR);
	if (master == -1) {
		pr_perror("open(%s) failed", "/dev/ptmx");
		return 1;
	}

	grantpt(master);
	unlockpt(master);

	slavename = ptsname(master);

	slave1 = open(slavename, O_RDWR);
	if (slave1 == -1) {
		pr_perror("open(%s) failed", slavename);
		return 1;
	}

	slave2 = open(slavename, O_RDWR);
	if (slave2 == -1) {
		pr_perror("open(%s) failed", slavename);
		return 1;
	}

	if (ioctl(slave1, TIOCSCTTY, 1)) {
		pr_perror("Can't set a controll terminal");
		return 1;
	}

	test_msg("Closing master\n");
	signal(SIGHUP, SIG_IGN);
	close(master);

	test_daemon();
	test_waitsig();

	close(slave1);
	close(slave2);

	pass();

	return 0;
}
