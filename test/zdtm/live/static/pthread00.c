/*
 * A simple testee program with threads
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <syscall.h>

#include "zdtmtst.h"

#define exit_group(code)	\
	syscall(__NR_exit_group, code)

const char *test_doc	= "Create a few pthreads/forks and compare TLS and mmap data on restore\n";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org";

static __thread char tls_data[10];

#define TRANSITION_PASSED	4
#define TRANSITION_FAILED	8

#define MAP(map, i)		(((int *)map)[i])

#define SET_PASSED(map, i)	MAP(map, i) = TRANSITION_PASSED
#define SET_FAILED(map, i)	MAP(map, i) = TRANSITION_FAILED

#define IS_PASSED(map, i)	(MAP(map, i) & TRANSITION_PASSED)

#define NR_WAITERS		6
static task_waiter_t waiter[NR_WAITERS];

#define passage(index)							\
	do {								\
		task_waiter_complete(&waiter[index], 1);		\
		task_waiter_wait4(&waiter[index], 2);			\
		if (memcmp(tls_data, __tls_data, sizeof(tls_data)))	\
			SET_FAILED(map, index);				\
		else							\
			SET_PASSED(map, index);				\
	} while (0)

static void *thread_subfunc_1(void *map)
{
	char __tls_data[10] = "1122334455";
	pid_t pid;
	int status;

	memcpy(tls_data, __tls_data, sizeof(tls_data));

	pid = test_fork();
	if (pid < 0) {
		exit_group(1);
	} else if (pid == 0) {
		passage(0);
		exit(0);
	}

	passage(1);

	test_msg("Waiting for %d\n", pid);
	waitpid(pid, &status, 0);

	return NULL;
}

static void *thread_func_1(void *map)
{
	char __tls_data[10] = "3122131212";
	pthread_t th;
	pid_t pid;
	int status;

	memcpy(tls_data, __tls_data, sizeof(tls_data));

	if (pthread_create(&th, NULL, &thread_subfunc_1, map)) {
		fail("Can't pthread_create");
		exit_group(1);
	}

	pid = test_fork();
	if (pid < 0) {
		fail("Failed to test_fork()\n");
		exit_group(1);
	} else if (pid == 0) {
		passage(2);
		exit(0);
	}

	passage(3);

	pthread_join(th, NULL);
	test_msg("Waiting for %d\n", pid);
	waitpid(pid, &status, 0);

	return NULL;
}

static void *thread_func_2(void *map)
{
	char __tls_data[10] = "wasdfrdgdc";
	pid_t pid;
	int status;

	memcpy(tls_data, __tls_data, sizeof(tls_data));

	pid = test_fork();
	if (pid < 0) {
		fail("Failed to test_fork()\n");
		exit_group(1);
	} else if (pid == 0) {
		passage(4);
		exit(0);
	}

	passage(5);

	test_msg("Waiting for %d\n", pid);
	waitpid(pid, &status, 0);

	return NULL;
}

int main(int argc, char *argv[])
{
	pthread_t th1, th2;
	int rc1, rc2, i;
	void *map;

	test_init(argc, argv);

	for (i = 0; i < NR_WAITERS; i++)
		task_waiter_init(&waiter[i]);

	test_msg("%s pid %d\n", argv[0], getpid());
	map = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (map == MAP_FAILED) {
		fail("Can't map");
		exit(1);
	}

	rc1 = pthread_create(&th1, NULL, &thread_func_1, map);
	rc2 = pthread_create(&th2, NULL, &thread_func_2, map);

	if (rc1 | rc2) {
		fail("Can't pthread_create");
		exit(1);
	}

	test_msg("Waiting until all threads are ready\n");

	for (i = NR_WAITERS - 1; i >= 0; i--)
		task_waiter_wait4(&waiter[i], 1);

	test_daemon();
	test_waitsig();

	for (i = 0; i < NR_WAITERS; i++)
		task_waiter_complete(&waiter[i], 2);

	test_msg("Waiting while all threads are joined\n");
	pthread_join(th1, NULL);
	pthread_join(th2, NULL);

	if (IS_PASSED(map, 0) &&
	    IS_PASSED(map, 1) &&
	    IS_PASSED(map, 2) &&
	    IS_PASSED(map, 3) &&
	    IS_PASSED(map, 4) &&
	    IS_PASSED(map, 5))
		pass();
	else
		fail();

	return 0;
}
