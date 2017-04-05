#include <unistd.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "zdtmtst.h"

const char *test_doc	= "Check for signalfd without signals";
const char *test_author	= "Pavel Emelyanov <xemul@parallels.com>";

int main(int argc, char *argv[])
{
	int fd, ret;
	sigset_t mask;
	siginfo_t info;

	test_init(argc, argv);

	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	fd = signalfd(-1, &mask, SFD_NONBLOCK);
	if (fd < 0) {
		fail("Can't create signalfd");
		exit(1);
	}

	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	sigaddset(&mask, SIGUSR2);
	sigprocmask(SIG_BLOCK, &mask, NULL);

	test_daemon();
	test_waitsig();

	kill(getpid(), SIGUSR2);

	ret = read(fd, &info, sizeof(info));
	if (ret >= 0) {
		fail("ghost signal");
		exit(1);
	}

	kill(getpid(), SIGUSR1);

	ret = read(fd, &info, sizeof(info));
	if (ret != sizeof(info)) {
		fail("no signal");
		exit(1);
	}

	if (info.si_signo != SIGUSR1) {
		fail("wrong signal");
		exit(1);
	}

	pass();
	return 0;
}
