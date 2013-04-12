#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include <sys/mman.h>
#include <sys/syscall.h>

#include "zdtmtst.h"

const char *test_doc	= "Check the futex robust list c/r";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

struct args {
	task_waiter_t	waiter;
	int		result;
};

static pid_t __gettid(void)
{
	return syscall(__NR_gettid);
}

void *thread_fn(void *arg)
{
	struct robust_list_head *head_orig = NULL, *head_new = NULL;
	size_t len_orig = 0, len_new = 0;
	struct args *args = arg;

	test_msg("Obtaining old RL\n");
	if (syscall(__NR_get_robust_list, __gettid(), &head_orig, &len_orig)) {
		args->result = -1;
		fail("__NR_get_robust_list failed");
	}

	test_msg("Complete\n");
	task_waiter_complete(&args->waiter, 1);
	if (args->result == -1)
		goto out;

	task_waiter_wait4(&args->waiter, 2);

	test_msg("Obtaining new RL\n");
	if (syscall(__NR_get_robust_list, __gettid(), &head_new, &len_new)) {
		args->result = -1;
		fail("__NR_get_robust_list failed");
	}
	if (args->result == -1)
		goto out;

	if (head_orig != head_new || len_orig != len_new) {
		args->result = -1;
		fail("comparison failed");
	}

	args->result = 0;
out:
	return NULL;
}

int main(int argc, char **argv)
{
	struct robust_list_head *head_orig = NULL, *head_new = NULL;
	size_t len_orig = 0, len_new = 0;
	pthread_t thread;
	struct args *args;

	test_init(argc, argv);

	args = (struct args *)mmap(NULL, sizeof(*args), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if ((void *)args == MAP_FAILED) {
		fail("mmap failed\n");
		exit(1);
	}

	test_msg("Obtaining old RL for thread-leader\n");
	if (syscall(__NR_get_robust_list, __gettid(), &head_orig, &len_orig)) {
		fail("__NR_get_robust_list failed");
		exit(1);
	}

	task_waiter_init(&args->waiter);
	args->result = 0;

	test_msg("Createing thread\n");
	if (pthread_create(&thread, NULL, thread_fn, (void *)args)) {
		fail("Can't create thread\n");
		exit(1);
	}

	test_msg("Wait for thread work\n");
	task_waiter_wait4(&args->waiter, 1);
	if (args->result == -1) {
		fail("thread failed\n");
		exit(1);
	}

	test_msg("C/R cycle\n");
	test_daemon();
	test_waitsig();

	task_waiter_complete(&args->waiter, 2);

	test_msg("Obtaining new RL for thread-leader\n");
	if (syscall(__NR_get_robust_list, __gettid(), &head_new, &len_new)) {
		fail("__NR_get_robust_list failed");
		exit(1);
	}

	if (head_orig != head_new || len_orig != len_new) {
		fail("comparison failed");
		exit(1);
	}

	pthread_join(thread, NULL);
	if (args->result)
		fail();
	else
		pass();

	munmap((void *)args, sizeof(*args));

	return 0;
}
