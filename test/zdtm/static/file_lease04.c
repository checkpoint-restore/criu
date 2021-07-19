#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <sys/wait.h>

#include "zdtmtst.h"

#define BREAK_SIGNUM SIGIO

const char *test_doc = "Check leases with no fds in owner process";
const char *test_author = "Pavel Begunkov <asml.silence@gmail.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

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

int main(int argc, char **argv)
{
	int fd = -1;
	int status, ret = -1;
	struct sigaction act = {};
	pid_t pid;

	test_init(argc, argv);

	act.sa_sigaction = break_sigaction;
	act.sa_flags = SA_SIGINFO;
	if (sigemptyset(&act.sa_mask) || sigaddset(&act.sa_mask, BREAK_SIGNUM) || sigaction(BREAK_SIGNUM, &act, NULL)) {
		pr_perror("Can't set signal action");
		return -1;
	}

	sigaction_error = 0;
	fd = prepare_file(filename, O_RDWR, O_WRONLY);
	if (fd < 0 || sigaction_error)
		goto done;

	pid = fork();
	if (pid < 0)
		return 1;
	if (pid == 0) {
		test_waitsig();
		if (check_lease_type(fd, F_UNLCK))
			return 1;
		close(fd);
		return 0;
	}
	close(fd);

	test_daemon();
	test_waitsig();

	kill(pid, SIGTERM);
	ret = waitpid(pid, &status, 0);

	if (ret < 0 || !WIFEXITED(status) || WEXITSTATUS(status))
		fail();
	else if (sigaction_error)
		fail("Ghost signal");
	else
		pass();
done:
	unlink(filename);
	return ret;
}
