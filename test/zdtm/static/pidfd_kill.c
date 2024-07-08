#include <sys/syscall.h>
#include <unistd.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc = "Kill child and grandchild process using pidfds\n";
const char *test_author = "Bhavik Sachdev <b.sachdev1904@gmail.com>";

static int pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

static int pidfd_send_signal(int pidfd, int sig, siginfo_t* info, unsigned int flags)
{
	return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
}

static int wait_for_child(int child)
{
	int status;
	if (waitpid(child, &status, 0) != child) {
		pr_perror("waitpid()");
		return 1;
	}

	if (status != 0) {
		test_msg("%d:%d:%d:%d", WIFEXITED(status), WEXITSTATUS(status),
			WIFSIGNALED(status), WTERMSIG(status));
	}

	return 0;
}

int main(int argc, char* argv[])
{
	#define READ 0
	#define WRITE 1

	int child, gchild, cpidfd, gpidfd, gchild_pid, ret;
	int p[2];

	if (pipe(p)) {
		pr_perror("pipe");
		return 1;
	}

	test_init(argc, argv);

	child = fork();
	if (child < 0) {
		pr_perror("fork");
		return 1;
	}

	if (child == 0) {
		gchild = fork();
		if (gchild < 0) {
			pr_perror("fork");
			return 1;
		}

		if (gchild == 0) {
			test_waitsig();
			return 0;
		}

		close(p[READ]);
		if (write(p[WRITE], &gchild, sizeof(gchild))
			!= sizeof(gchild)) {
			pr_perror("write");
			return 1;
		}
		close(p[WRITE]);

		test_waitsig();
		return wait_for_child(gchild);
	}

	cpidfd = pidfd_open(child, 0);
	if (cpidfd < 0) {
		pr_perror("pidfd_open");
		return 1;
	}

	close(p[WRITE]);
	if (read(p[READ], &gchild_pid, sizeof(gchild_pid))
		!= sizeof(gchild_pid)) {
		pr_perror("read");
		return 1;
	}
	close(p[READ]);

	gpidfd = pidfd_open(gchild_pid, 0);
	if (gpidfd < 0) {
		pr_perror("pidfd_open");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (pidfd_send_signal(gpidfd, SIGKILL, NULL, 0)) {
		pr_perror("Could not send signal");
		goto fail_close;
	}

	if (pidfd_send_signal(cpidfd, SIGKILL, NULL, 0)) {
		pr_perror("Could not send signal");
		goto fail_close;
	}

	ret = wait_for_child(child);
	if (ret)
		goto fail_close;

	pass();
	close(cpidfd);
	close(gpidfd);
	return 0;

fail_close:
	fail();
	close(cpidfd);
	close(gpidfd);
	return 1;
}
