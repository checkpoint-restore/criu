#include <sys/syscall.h>
#include <unistd.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc = "Checks pidfd sends signal to child process after restore\n";
const char *test_author = "Bhavik Sachdev <b.sachdev1904@gmail.com>";

static int pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

static int pidfd_send_signal(int pidfd, int sig, siginfo_t* info, unsigned int flags)
{
	return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
}

int main(int argc, char* argv[])
{
	int pidfd, status;
	pid_t child;

	test_init(argc, argv);

	child = fork();
	if (child < 0) {
		pr_perror("Unable to fork a new process");
		return 1;
	} else if (child == 0) {
		test_waitsig();
		return 0;
	}

	pidfd = pidfd_open(child, 0);
	if (pidfd < 0) {
		pr_perror("pidfd_open failed");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (pidfd_send_signal(pidfd, SIGTERM, NULL, 0)) {
		fail("Could not send signal");
		goto err_close;
	}

	if (waitpid(child, &status, 0) != child) {
		pr_perror("waitpid()");
		goto err_close;
	}

	if (status != 0) {
		fail("%d:%d:%d:%d", WIFEXITED(status), WEXITSTATUS(status), WIFSIGNALED(status), WTERMSIG(status));
		goto err_close;
	}

	pass();
	close(pidfd);
	return 0;
err_close:
	close(pidfd);
	return 1;
}
