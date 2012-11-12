#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>

#include "zdtmtst.h"

#define gettid()	pthread_self()

const char *test_doc	= "Create a few pthreads and test TLS + blocked signals\n";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org";

static __thread struct tls_data_s {
	char		*rand_string[10];
	sigset_t	blk_sigset;
} tls_data;

static task_waiter_t t1;
static task_waiter_t t2;

static void show_sigset(const sigset_t *s)
{
	const char *p = (void *)s;
	char buf[1024];
	size_t i;

	for (i = 0; i < sizeof(s); i++)
		sprintf(&buf[i * 2], "%02x", p[i]);
	test_msg("sigset: %s\n", buf);
}

static void *ch_thread_2(void *arg)
{
	char __tls_data[sizeof(tls_data.rand_string)] = "XM5o:?B*[a";
	int *results_map = arg;
	sigset_t blk_sigset;
	sigset_t new;

	memcpy(tls_data.rand_string, __tls_data, sizeof(tls_data.rand_string));

	sigemptyset(&blk_sigset);
	sigprocmask(SIG_SETMASK, NULL, &blk_sigset);
	sigaddset(&blk_sigset, SIGFPE);
	sigprocmask(SIG_SETMASK, &blk_sigset, NULL);
	memcpy(&tls_data.blk_sigset, &blk_sigset, sizeof(tls_data.blk_sigset));

	task_waiter_complete(&t2, 1);
	task_waiter_wait4(&t2, 2);

	if (memcmp(tls_data.rand_string, __tls_data, sizeof(tls_data.rand_string))) {
		err("Failed to restore tls_data.rand_string in thread 2\n");
		results_map[2] = -1;
	} else
		results_map[2] = 1;

	if (memcmp(&tls_data.blk_sigset, &blk_sigset, sizeof(tls_data.blk_sigset))) {
		err("Failed to restore tls_data.blk_sigset in thread 2\n");
		results_map[4] = -1;
	} else
		results_map[4] = 1;

	sigprocmask(SIG_SETMASK, NULL, &new);
	if (memcmp(&tls_data.blk_sigset, &new, sizeof(tls_data.blk_sigset))) {
		err("Failed to restore blk_sigset in thread 2\n");
		results_map[6] = -1;

		show_sigset(&tls_data.blk_sigset);
		show_sigset(&new);
	} else
		results_map[6] = 1;

	return NULL;
}

static void *ch_thread_1(void *arg)
{
	char __tls_data[sizeof(tls_data.rand_string)] = "pffYQSBo?6";
	int *results_map = arg;
	sigset_t blk_sigset;
	sigset_t new;

	memcpy(tls_data.rand_string, __tls_data, sizeof(tls_data.rand_string));

	sigemptyset(&blk_sigset);
	sigprocmask(SIG_SETMASK, NULL, &blk_sigset);
	sigaddset(&blk_sigset, SIGTRAP);
	sigprocmask(SIG_SETMASK, &blk_sigset, NULL);
	memcpy(&tls_data.blk_sigset, &blk_sigset, sizeof(tls_data.blk_sigset));

	task_waiter_complete(&t1, 1);
	task_waiter_wait4(&t1, 2);

	if (memcmp(tls_data.rand_string, __tls_data, sizeof(tls_data.rand_string))) {
		err("Failed to restore tls_data.rand_string in thread 1\n");
		results_map[1] = -1;
	} else
		results_map[1] = 1;

	if (memcmp(&tls_data.blk_sigset, &blk_sigset, sizeof(tls_data.blk_sigset))) {
		err("Failed to restore tls_data.blk_sigset in thread 1\n");
		results_map[3] = -1;
	} else
		results_map[3] = 1;

	sigemptyset(&new);
	sigprocmask(SIG_SETMASK, NULL, &new);
	if (memcmp(&tls_data.blk_sigset, &new, sizeof(tls_data.blk_sigset))) {
		err("Failed to restore blk_sigset in thread 1\n");
		results_map[5] = -1;

		show_sigset(&tls_data.blk_sigset);
		show_sigset(&new);
	} else
		results_map[5] = 1;

	return NULL;
}

int main(int argc, char *argv[])
{
	pthread_t thread_1, thread_2;
	int *results_map;
	int rc1, rc2;

	test_init(argc, argv);

	task_waiter_init(&t1);
	task_waiter_init(&t2);

	test_msg("%s pid %d\n", argv[0], getpid());

	results_map = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if ((void *)results_map == MAP_FAILED) {
		fail("Can't map");
		exit(1);
	}

	rc1 = pthread_create(&thread_1, NULL, &ch_thread_1, results_map);
	rc2 = pthread_create(&thread_2, NULL, &ch_thread_2, results_map);

	if (rc1 | rc2) {
		fail("Can't pthread_create");
		exit(1);
	}

	test_msg("Waiting until all threads are created\n");

	task_waiter_wait4(&t1, 1);
	task_waiter_wait4(&t2, 1);

	test_daemon();
	test_waitsig();

	task_waiter_complete(&t1, 2);
	task_waiter_complete(&t2, 2);

	test_msg("Waiting while all threads are joined\n");
	pthread_join(thread_1, NULL);
	pthread_join(thread_2, NULL);

	if (results_map[1] == 1 &&
	    results_map[2] == 1 &&
	    results_map[3] == 1 &&
	    results_map[4] == 1 &&
	    results_map[5] == 1 &&
	    results_map[6] == 1)
		pass();
	else
		fail();

	return 0;
}
