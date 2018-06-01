#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <syscall.h>

#include <sys/types.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc	= "Check for alternate signal stack";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

static char stack_thread[SIGSTKSZ + TEST_MSG_BUFFER_SIZE] __stack_aligned__;
static char stack_main[SIGSTKSZ + TEST_MSG_BUFFER_SIZE] __stack_aligned__;

enum {
	SAS_MAIN_OLD,
	SAS_MAIN_NEW,
	SAS_THRD_OLD,
	SAS_THRD_NEW,

	SAS_MAX
};
static stack_t sas_state[SAS_MAX];

static task_waiter_t t;

#define exit_group(code)	syscall(__NR_exit_group, code)
#define gettid()		syscall(__NR_gettid)

static int sascmp(stack_t *old, stack_t *new)
{
	return old->ss_size != new->ss_size	||
		old->ss_sp != new->ss_sp	||
		old->ss_flags != new->ss_flags;
}

static void show_ss(char *prefix, stack_t *s)
{
	test_msg("%20s: at %p (size %8zu flags %#2x)\n",
		 prefix, s->ss_sp, s->ss_size, s->ss_flags);
}

void thread_sigaction(int signo, siginfo_t *info, void *context)
{
	if (sigaltstack(NULL, &sas_state[SAS_THRD_NEW]))
		pr_perror("thread sigaltstack");

	show_ss("thread in sas", &sas_state[SAS_THRD_NEW]);

	task_waiter_complete(&t, 2);

	test_msg("Waiting in thread SAS\n");
	task_waiter_wait4(&t, 3);
	test_msg("Leaving thread SAS\n");
}

static void *thread_func(void *arg)
{
	sas_state[SAS_THRD_OLD] = (stack_t) {
		.ss_size	= sizeof(stack_thread) - 8,
		.ss_sp		= stack_thread,
		.ss_flags	= 0,
	};

	struct sigaction sa = {
		.sa_sigaction	= thread_sigaction,
		.sa_flags	= SA_RESTART | SA_ONSTACK,
	};

	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGUSR2, &sa, NULL)) {
		pr_perror("Can't set SIGUSR2 handler");
		exit_group(-1);
	}

	task_waiter_wait4(&t, 1);

	if (sigaltstack(&sas_state[SAS_THRD_OLD], NULL)) {
		pr_perror("thread sigaltstack");
		exit_group(-1);
	}

	syscall(__NR_tkill, gettid(), SIGUSR2);

	return NULL;
}

void leader_sigaction(int signo, siginfo_t *info, void *context)
{
	if (sigaltstack(NULL, &sas_state[SAS_MAIN_NEW]))
		pr_perror("leader sigaltstack");

	show_ss("leader in sas", &sas_state[SAS_MAIN_NEW]);
}

int main(int argc, char *argv[])
{
	pthread_t thread;

	sas_state[SAS_MAIN_OLD] = (stack_t) {
		.ss_size	= sizeof(stack_main) - 8,
		.ss_sp		= stack_main,
		.ss_flags	= 0,
	};

	struct sigaction sa = {
		.sa_sigaction	= leader_sigaction,
		.sa_flags	= SA_RESTART | SA_ONSTACK,
	};

	sigemptyset(&sa.sa_mask);

	test_init(argc, argv);
	task_waiter_init(&t);

	if (sigaction(SIGUSR1, &sa, NULL)) {
		pr_perror("Can't set SIGUSR1 handler");
		exit(-1);
	}

	if (pthread_create(&thread, NULL, &thread_func, NULL)) {
		pr_perror("Can't create thread");
		exit(-1);
	}

	if (sigaltstack(&sas_state[SAS_MAIN_OLD], NULL)) {
		pr_perror("sigaltstack");
		exit(-1);
	}

	task_waiter_complete(&t, 1);
	task_waiter_wait4(&t, 2);

	test_daemon();
	test_waitsig();

	test_msg("Thread may leave SAS\n");
	task_waiter_complete(&t, 3);

	syscall(__NR_tkill, gettid(), SIGUSR1);

	if (pthread_join(thread, NULL)) {
		fail("Error joining thread");
		exit(-1);
	}
	task_waiter_fini(&t);

	sas_state[SAS_THRD_OLD].ss_flags = SS_ONSTACK;
	sas_state[SAS_MAIN_OLD].ss_flags = SS_ONSTACK;

	show_ss("main old", &sas_state[SAS_MAIN_OLD]);
	show_ss("main new", &sas_state[SAS_MAIN_NEW]);
	show_ss("thrd old", &sas_state[SAS_THRD_OLD]);
	show_ss("thrd new", &sas_state[SAS_THRD_NEW]);

	if (sascmp(&sas_state[SAS_MAIN_OLD], &sas_state[SAS_MAIN_NEW]) ||
	    sascmp(&sas_state[SAS_THRD_OLD], &sas_state[SAS_THRD_NEW])) {
		fail("sas not restored");
	} else
		pass();

	return 0;
}
