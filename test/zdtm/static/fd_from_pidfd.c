#include <sys/syscall.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check if fd obtained from pidfd_get_fd is C/R correctly\n";
const char *test_author = "Bhavik Sachdev <b.sachdev1904@gmail.com>";

static int pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

static int pidfd_getfd(int pidfd, int targetfd, unsigned int flags)
{
	return syscall(__NR_pidfd_getfd, pidfd, targetfd, flags);
}

static int pidfd_send_signal(int pidfd, int sig, siginfo_t* info, unsigned int flags)
{
	return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
}

int main(int argc, char* argv[])
{
	#define READ 0
	#define WRITE 1

	int pidfd, child, p[2], child_read, read_data, status;
	int data = 42;

	test_init(argc, argv);

	if (pipe(p)) {
		pr_perror("pipe");
		return 1;
	}

	child = fork();
	if (child < 0) {
		pr_perror("fork");
		return 1;
	}

	if (child == 0) {
		close(p[WRITE]);
		test_waitsig();
		return 0;
	}

	pidfd = pidfd_open(child, 0);
	if (pidfd < 0) {
		pr_perror("pidfd_open failed");
		return 1;
	}

	close(p[READ]);
	if (write(p[WRITE], &data, sizeof(data)) != sizeof(data)) {
		pr_perror("write");
		return 1;
	}
	close(p[WRITE]);

	child_read = pidfd_getfd(pidfd, p[READ], 0);
	if (child_read < 0) {
		pr_perror("pidfd_getfd");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (read(child_read, &read_data, sizeof(read_data)) != sizeof(read_data)) {
		pr_perror("read");
		goto err_close;
	}

	if (read_data != data) {
		fail("data from fd obtained using pidfd_getfd incorrect");
		goto err_close;
	}

	if (pidfd_send_signal(pidfd, SIGTERM, NULL, 0)) {
		pr_perror("Could not send signal");
		goto err_close;
	}

	if (waitpid(child, &status, 0) != child) {
		pr_perror("waitpid()");
		return 1;
	}

	if (status != 0) {
		fail("%d:%d:%d:%d", WIFEXITED(status), WEXITSTATUS(status), WIFSIGNALED(status), WTERMSIG(status));
		return 1;
	}

	pass();
	close(child_read);
	close(pidfd);
	return 0;
err_close:
	close(child_read);
	close(pidfd);
	return 1;
}
