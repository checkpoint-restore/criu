#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <sched.h>
#include <sys/mman.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/wait.h>
#include <fcntl.h>

#define STACK_SIZE	(8 * 4096)

static int sig_received;
static char dir[PATH_MAX];
static char name[PATH_MAX];
int status_pipe[2];

static void sig_hand(int signo)
{
	sig_received = signo;
}
void test_waitsig(void)
{
	sigset_t mask, oldmask;

	/* Set up the mask of signals to temporarily block. */
	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGCHLD);

	/* Wait for a signal to arrive. */
	sigprocmask(SIG_BLOCK, &mask, &oldmask);
	while (!sig_received)
		sigsuspend (&oldmask);
	sigprocmask (SIG_UNBLOCK, &mask, NULL);

	sig_received = 0;
}

int fn(void *_arg)
{
	struct sigaction sa = {
		.sa_handler	= sig_hand,
		.sa_flags	= SA_RESTART,
	};
	char cmd[256];
	int ret;

	close(status_pipe[0]);
	ret = fcntl(status_pipe[1], F_SETFD, FD_CLOEXEC);
	if (ret == -1) {
		fprintf(stderr, "fcntl failed %m\n");
		exit(1);
	}

	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGTERM, &sa, NULL)) {
		fprintf(stderr, "Can't set SIGTERM handler: %m\n");
		exit(1);
	}

	/* Start test */
	snprintf(cmd, sizeof(cmd), "make -C %s %s.pid", dir, name);
	ret = system(cmd);

	/* Daemonize */
	write(status_pipe[1], &ret, sizeof(ret));
	close(status_pipe[1]);
	if (ret)
		return ret;

	/* suspend/resume */
	test_waitsig();

	/* Stop test */
	snprintf(cmd, sizeof(cmd), "make -C %s %s.out", dir, name);
	ret = system(cmd);
	if (ret)
		return ret;

	ret = 0;
	while (ret != -1)
		ret = wait(NULL);

	return 0;
}

int main(int argc, char *argv[])
{
	void *stack;
	pid_t pid;
	int ret, status;

	if (argc < 3)
		exit(1);

	strcpy(dir, argv[1]);
	strcpy(name, argv[2]);

	stack = mmap(NULL, STACK_SIZE, PROT_WRITE | PROT_READ,
			MAP_PRIVATE | MAP_GROWSDOWN | MAP_ANONYMOUS, -1, 0);
	if (stack == MAP_FAILED) {
		fprintf(stderr, "Can't map stack %m\n");
		exit(1);
	}
	ret = pipe(status_pipe);
	if (ret) {
		fprintf(stderr, "Pipe() failed %m\n");
		exit(1);
	}
	pid = clone(fn, stack + STACK_SIZE, CLONE_NEWPID | SIGCHLD, NULL);
	if (pid < 0) {
		fprintf(stderr, "clone() failed: %m\n");
		exit(1);
	}
	status = 1;
	ret = read(status_pipe[0], &status, sizeof(status));
	if (ret != sizeof(status) || status)
		exit(1);
	return 0;
}
