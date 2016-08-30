#define _XOPEN_SOURCE 500
#include <stdlib.h>
#include "zdtmtst.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <termios.h>
#include <sys/ioctl.h>

const char *test_doc	= "Check a non-controling terminal";
const char *test_author	= "Andrey Vagin <avagin@openvz.org>";

int main(int argc, char ** argv)
{
	int fdm, fds;
	char *slavename;
	pid_t sid;

	test_init(argc, argv);

	setsid();

	fdm = open("/dev/ptmx", O_RDWR);
	if (fdm == -1) {
		pr_perror("Can't open a master pseudoterminal");
		return 1;
	}

	grantpt(fdm);
	unlockpt(fdm);
	slavename = ptsname(fdm);

	/* set up a controlling terminal */
	fds = open(slavename, O_RDWR | O_NOCTTY);
	if (fds == -1) {
		pr_perror("Can't open a slave pseudoterminal %s", slavename);
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (ioctl(fds, TIOCGSID, &sid) != -1 || errno != ENOTTY) {
		fail("The tty is a controlling for someone");
		return 1;
	}

	pass();

	return 0;
}
