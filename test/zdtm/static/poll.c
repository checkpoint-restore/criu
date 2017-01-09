#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <utime.h>
#include <time.h>

#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc	= "Check poll() timeouts";
const char *test_author	= "Cyrill Gorcunov <gorcunov@parallels.com>";

static void show_timestamp(char *prefix, unsigned long tv_sec, unsigned long tv_usec)
{
	test_msg("%8s: sec %20lu nsec %20lu\n", prefix, tv_sec, tv_usec);
}

static void show_pollfd(struct pollfd *fds, size_t nfds)
{
	size_t i;

	for (i = 0; i < nfds; i++) {
		test_msg("%2zu) fd: %2d events %2x revents %2x\n",
			 i, fds[i].fd, fds[i].events, fds[i].revents);
	}
}

int main(int argc, char *argv[])
{
	struct timeval time1, time2;
	struct timespec delay;
	struct pollfd ufds[2];
	int pipes[2], ret;
	int delta, status;
	task_waiter_t t;
	pid_t pid;
	char *deltaenv;

	test_init(argc, argv);
	task_waiter_init(&t);

	if (pipe(pipes)) {
		pr_perror("Can't create pipes");
		exit(1);
	}

	memset(ufds, 0, sizeof(ufds));
	ufds[0].fd = pipes[0];
	ufds[0].events = POLLIN;

	ufds[1].fd = pipes[1];
	ufds[1].events = POLLIN;

	show_pollfd(ufds, 2);

	if (gettimeofday(&time1, NULL)) {
		pr_perror("Can't get first delta");
		exit(1);
	}
	show_timestamp("Init", time1.tv_sec, time1.tv_usec);

	pid = test_fork();
	if (pid < 0) {
		pr_perror("Fork failed");
		exit(1);
	} else if (pid == 0) {
		if (gettimeofday(&time1, NULL)) {
			pr_perror("Can't get from times");
			exit(1);
		}

		show_timestamp("Start", time1.tv_sec, time1.tv_usec);

		task_waiter_complete(&t, 1);
		deltaenv = getenv("ZDTM_DELTA");
		if (deltaenv)
			delta = atoi(deltaenv);
		else
			delta = 5;
		while (test_go()) {
			ret = poll(ufds, 2, delta * 1000);
			show_pollfd(ufds, 2);
			if (ret && errno != EINTR) {
				pr_perror("Poll-2 returned %d (events?!)", ret);
				exit(1);
			}

			if (gettimeofday(&time2, NULL)) {
				pr_perror("Can't get from times");
				exit(1);
			}

			show_timestamp("Stop", time2.tv_sec, time2.tv_usec);
			show_timestamp("Diff", time2.tv_sec - time1.tv_sec,
				       time2.tv_usec - time1.tv_usec);
			if ((time2.tv_sec - time1.tv_sec) > delta) {
				fail("Delta is too big %lu",
				     (unsigned long)(time2.tv_sec - time1.tv_sec));
				exit(1);
			}
		}
		exit(0);
	}

	task_waiter_wait4(&t, 1);

	/* Wait to make sure we're in poll internals */
	delay.tv_sec = 1;
	delay.tv_nsec = 0;
	nanosleep(&delay, NULL);

	test_daemon();
	test_waitsig();
	kill(pid, SIGTERM);

	/* Return immediately if child run or stopped(by SIGSTOP) */
	if (waitpid(pid, &status, 0) == -1) {
		pr_perror("Unable to wait child");
		exit(1);
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		fail("Child exited with error");
		exit(1);
	}

	pass();
	return 0;
}
