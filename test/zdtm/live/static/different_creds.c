#define _GNU_SOURCE
#include <alloca.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <sched.h>
#include <sys/capability.h>
#include <linux/limits.h>
#include <pthread.h>
#include <syscall.h>
#include <sys/socket.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that threads with different creds aren't checkpointed";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

void *drop_caps_and_wait(void *arg)
{
	int fd = *((int *) arg);
	void *retcode = (void *)0xdeadbeaf;
	cap_t caps;
	char c;

        caps = cap_get_proc();
        if (!caps) {
                pr_perror("cap_get_proc");
                return NULL;
        }

        if (cap_clear_flag(caps, CAP_EFFECTIVE) < 0) {
                pr_perror("cap_clear_flag");
                goto die;
        }

        if (cap_set_proc(caps) < 0) {
                pr_perror("cap_set_proc");
                goto die;
        }

	if (write(fd, "a", 1) != 1) {
		pr_perror("Unable to send a status");
		goto die;
	}

	if (read(fd, &c, 1) != 1) {
		pr_perror("Unable to read a status");
		goto die;
	}

	retcode = NULL;
die:
        cap_free(caps);
	return retcode;
}

int main(int argc, char ** argv)
{
	int pipefd[2];
	pthread_t thr;
	char c;
	void *retcode;

	test_init(argc, argv);

	if (socketpair(AF_FILE, SOCK_SEQPACKET, 0, pipefd)) {
		pr_perror("pipe");
		return -1;
	}

	if (pthread_create(&thr, NULL, drop_caps_and_wait, &pipefd[0])) {
		pr_perror("Unable to create thread");
		return -1;
	}

	/*
	 * Wait for child to signal us that it has droped caps.
	 */
	if (read(pipefd[1], &c, 1) != 1) {
		pr_perror("read");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (write(pipefd[1], &c, 1) != 1) {
		pr_perror("write");
		return 1;
	}

	if (pthread_join(thr, &retcode)) {
		pr_perror("Unable to jount a thread");
		return 1;
	}
	if (retcode != NULL)
		return 1;

	pass();

	return 0;
}
