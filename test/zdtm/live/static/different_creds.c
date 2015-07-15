#define _GNU_SOURCE
#include <alloca.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <sched.h>
#include <sys/capability.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that threads with different creds aren't checkpointed";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

int drop_caps_and_wait(void *arg)
{
	cap_t caps;
	int *pipe = arg;

        caps = cap_get_proc();
        if (!caps) {
                err("cap_get_proc");
                return 1;
        }

        if (cap_clear_flag(caps, CAP_EFFECTIVE) < 0) {
                err("cap_clear_flag");
                goto die;
        }

        if (cap_set_proc(caps) < 0) {
                err("cap_set_proc");
                goto die;
        }

	close(*pipe);

	while(1)
		sleep(1000);
die:
        cap_free(caps);
        return 1;
}

int main(int argc, char ** argv)
{
	pid_t pid;
	int ret, pipefd[2];
	long clone_flags = CLONE_VM | CLONE_FILES | CLONE_SIGHAND |
			   CLONE_THREAD | CLONE_SYSVSEM;

        size_t stack_size = sysconf(_SC_PAGESIZE);
        void *stack = alloca(stack_size);
	char buf;

	test_init(argc, argv);

	if (pipe(pipefd) < 0) {
		err("pipe");
		return -1;
	}

	pid = clone(drop_caps_and_wait, stack + stack_size, clone_flags, pipefd);
	if (pid < 0) {
		err("fork");
		return -1;
	}

	close(pipefd[1]);

	/*
	 * Wait for child to signal us that it has droped caps.
	 */
	ret = read(pipefd[0], &buf, 1);
	close(pipefd[0]);
	if (ret < 0) {
		err("read");
		return 1;
	}

	test_daemon();
	test_waitsig();

	fail("shouldn't dump successfully");

	kill(pid, SIGKILL);
	return ret;
}
