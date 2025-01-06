#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <limits.h>

#include "zdtmtst.h"

#define FD_COUNT     3
#define BREAK_SIGNUM SIGIO

const char *test_doc = "Check c/r of breaking leases";
const char *test_author = "Pavel Begunkov <asml.silence@gmail.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

char filename1[PATH_MAX];
char filename2[PATH_MAX];
char filename3[PATH_MAX];

int expected_fd;
int sigaction_error;

static void break_sigaction(int signo, siginfo_t *info, void *ctx)
{
	if (signo != BREAK_SIGNUM) {
		pr_err("Unexpected signal(%i)\n", signo);
		sigaction_error = -1;
	} else if (info->si_fd != expected_fd) {
		pr_err("Unexpected fd(%i)\n", info->si_fd);
		sigaction_error = -1;
	}
	expected_fd = -1;
}

static int check_lease_type(int fd, int expected_type)
{
	int lease_type = fcntl(fd, F_GETLEASE);

	if (lease_type != expected_type) {
		if (lease_type < 0)
			pr_perror("Can't acquire lease type");
		else
			pr_err("Mismatched lease type: %i\n", lease_type);
		return -1;
	}
	return 0;
}

static int prepare_file(char *file, int file_type, int break_type)
{
	int fd, fd_break;
	int lease_type = (file_type == O_RDONLY) ? F_RDLCK : F_WRLCK;

	fd = open(file, file_type | O_CREAT, 0666);
	if (fd < 0) {
		pr_perror("Can't open file (type %i)", file_type);
		return fd;
	}
	if (fcntl(fd, F_SETLEASE, lease_type) < 0) {
		pr_perror("Can't set exclusive lease");
		goto err;
	}
	if (fcntl(fd, F_SETSIG, BREAK_SIGNUM) < 0) {
		pr_perror("Can't set signum for file i/o");
		goto err;
	}

	expected_fd = fd;
	fd_break = open(file, break_type | O_NONBLOCK);

	if (fd_break >= 0) {
		close(fd_break);
		pr_err("Conflicting lease not found\n");
		goto err;
	} else if (errno != EWOULDBLOCK) {
		pr_perror("Can't break lease");
		goto err;
	}
	return fd;
err:
	close(fd);
	return -1;
}

static void close_files(int fds[FD_COUNT])
{
	int i;

	for (i = 0; i < FD_COUNT; ++i)
		if (fds[i] >= 0)
			close(fds[i]);

	unlink(filename1);
	unlink(filename2);
	unlink(filename3);
}

int main(int argc, char **argv)
{
	int fds[FD_COUNT] = {};
	int ret = -1;
	struct sigaction act = {};

	test_init(argc, argv);

	snprintf(filename1, sizeof(filename1), "%s.0", filename);
	snprintf(filename2, sizeof(filename2), "%s.1", filename);
	snprintf(filename3, sizeof(filename3), "%s.2", filename);

	act.sa_sigaction = break_sigaction;
	act.sa_flags = SA_SIGINFO;

	if (sigemptyset(&act.sa_mask) || sigaddset(&act.sa_mask, BREAK_SIGNUM) || sigaction(BREAK_SIGNUM, &act, NULL)) {
		pr_perror("Can't set signal action");
		fail();
		return -1;
	}

	sigaction_error = 0;
	fds[0] = prepare_file(filename1, O_RDONLY, O_WRONLY);
	fds[1] = prepare_file(filename2, O_WRONLY, O_RDONLY);
	fds[2] = prepare_file(filename3, O_WRONLY, O_WRONLY);
	if (fds[0] < 0 || fds[1] < 0 || fds[2] < 0 || sigaction_error)
		goto done;

	test_daemon();
	test_waitsig();

	ret = 0;
	if (sigaction_error)
		fail("Ghost signal");
	else if (check_lease_type(fds[0], F_UNLCK) || check_lease_type(fds[1], F_RDLCK) ||
		 check_lease_type(fds[2], F_UNLCK))
		fail("Lease type doesn't match");
	else
		pass();
done:
	close_files(fds);
	return ret;
}
