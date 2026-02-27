#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc = "Check broken read-lease is restored with correct type";
const char *test_author = "CRIU";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

static void break_sigaction(int signo, siginfo_t *info, void *ctx)
{
}

int main(int argc, char **argv)
{
	struct sigaction act = {};
	int fd;

	test_init(argc, argv);

	act.sa_sigaction = break_sigaction;
	act.sa_flags = SA_SIGINFO | SA_RESTART;
	if (sigaction(SIGIO, &act, NULL)) {
		pr_perror("Can't set signal action");
		return 1;
	}

	fd = open(filename, O_RDONLY | O_CREAT, 0666);
	if (fd < 0) {
		pr_perror("Can't open file");
		return 1;
	}

	if (fcntl(fd, F_SETLEASE, F_RDLCK) < 0) {
		pr_perror("Can't set read lease");
		return 1;
	}

	if (fcntl(fd, F_SETSIG, SIGIO) < 0) {
		pr_perror("Can't set lease signal");
		return 1;
	}

	{
		int fd_break = open(filename, O_WRONLY | O_NONBLOCK);
		if (fd_break >= 0) {
			close(fd_break);
			pr_err("Conflicting lease not found\n");
			return 1;
		} else if (errno != EWOULDBLOCK) {
			pr_perror("Can't break lease");
			return 1;
		}
	}

	test_daemon();
	test_waitsig();

	{
		int fd_check = open(filename, O_RDONLY | O_NONBLOCK);
		if (fd_check >= 0) {
			close(fd_check);
		} else if (errno == EWOULDBLOCK) {
			fail("Unexpected lease has been found");
			return 1;
		} else {
			pr_perror("unexpected error");
			return 1;
		}
	}
	{
		int fd_break = open(filename, O_WRONLY | O_NONBLOCK);
		if (fd_break >= 0) {
			close(fd_break);
			fail("Conflicting lease not found\n");
			return 1;
		} else if (errno != EWOULDBLOCK) {
			pr_perror("unexpected error");
			return 1;
		}
	}
	pass();
	return 0;
}
