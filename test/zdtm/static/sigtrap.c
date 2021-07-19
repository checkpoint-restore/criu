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

const char *test_doc = "Check that a pending SIGTRAP handled correctly";
const char *test_author = "Andrei Vagin <avagin@gmail.com>";

static void sigh(int signo)
{
}

int main(int argc, char *argv[])
{
	int fd, ret;
	sigset_t mask;
	siginfo_t info;
	struct sigaction act = {
		.sa_handler = sigh,
	};

	test_init(argc, argv);

	if (sigaction(SIGTRAP, &act, NULL)) {
		pr_perror("sigaction");
		exit(1);
	}

	sigemptyset(&mask);
	sigaddset(&mask, SIGTRAP);
	fd = signalfd(-1, &mask, SFD_NONBLOCK);
	if (fd < 0) {
		fail("Can't create signalfd");
		exit(1);
	}

	sigemptyset(&mask);
	sigaddset(&mask, SIGTRAP);
	sigprocmask(SIG_BLOCK, &mask, NULL);
	kill(getpid(), SIGTRAP);

	test_daemon();
	test_waitsig();

	ret = read(fd, &info, sizeof(info));
	if (ret < 0) {
		fail("can't read signals");
		exit(1);
	}

	if (info.si_signo != SIGTRAP) {
		fail("wrong signal");
		exit(1);
	}

	if (sigaction(SIGTRAP, NULL, &act)) {
		pr_perror("sigaction");
		exit(1);
	}

	if (act.sa_handler != sigh) {
		fail("unexpected sighanl hanlder");
		exit(1);
	}

	pass();
	return 0;
}
