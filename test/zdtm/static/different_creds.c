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
	int fd = *((int *) arg), i;
	void *retcode = (void *)0xdeadbeaf;
	cap_t caps;
	char c;

	typedef struct cap_set {
		cap_flag_value_t	val;
		cap_flag_value_t	new;
		cap_flag_t		flag;
		cap_value_t		bit;
	} cap_set_t;

	cap_set_t src[] = {
		{
			.val	= CAP_CLEAR,
			.flag	= CAP_EFFECTIVE,
			.bit	= CAP_CHOWN,
		},
		{
			.val	= CAP_SET,
			.flag	= CAP_EFFECTIVE,
			.bit	= CAP_DAC_OVERRIDE,
		},
		{
			.val	= CAP_CLEAR,
			.flag	= CAP_INHERITABLE,
			.bit	= CAP_SETPCAP,
		},
		{
			.val	= CAP_SET,
			.flag	= CAP_INHERITABLE,
			.bit	= CAP_NET_BIND_SERVICE,
		},
	};

        caps = cap_get_proc();
        if (!caps) {
                pr_perror("cap_get_proc");
                return NULL;
        }

	for (i = 0; i < ARRAY_SIZE(src); i++) {
		if (cap_set_flag(caps, src[i].flag, 1, &src[i].bit, src[i].val) < 0) {
			pr_perror("Can't setup CAP %s", cap_to_name(src[i].bit));
			goto die;
		}
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

	for (i = 0; i < ARRAY_SIZE(src); i++) {
		if (cap_get_flag(caps, src[i].bit, src[i].flag, &src[i].new) < 0) {
			pr_perror("Can't get CAP %s", cap_to_name(src[i].bit));
			goto die;
		}

		if (src[i].val != src[i].new) {
			pr_err("Val mismatch on CAP %s\n", cap_to_name(src[i].bit));
			goto die;
		}
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
	 * Wait for child to signal us that it has dropped caps.
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

	if (retcode != NULL) {
		fail("retcode returned %p", retcode);
		return 1;
	}

	pass();

	return 0;
}
