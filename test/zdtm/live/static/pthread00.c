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

#include "zdtmtst.h"

#define gettid()	pthread_self()

const char *test_doc	= "Create a few pthreads/forks and compare TLS and mmap data on restore\n";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org";

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static __thread char tls_data[10];

#define TRANSITION_CREATED	1
#define TRANSITION_STARTED	2
#define TRANSITION_PASSED	4
#define TRANSITION_FAILED	8

#define MAP(map, i)		(((int *)map)[i])

#define SET_CREATED(map, i)	MAP(map, i) |= TRANSITION_CREATED
#define SET_STARTED(map, i)	MAP(map, i) |= TRANSITION_STARTED
#define SET_PASSED(map, i)	MAP(map, i) |= TRANSITION_PASSED
#define SET_FAILED(map, i)	MAP(map, i) |= TRANSITION_FAILED

#define IS_CREATED(map, i)	(MAP(map, i) & TRANSITION_CREATED)
#define IS_STARTED(map, i)	(MAP(map, i) & TRANSITION_STARTED)
#define IS_PASSED(map, i)	(MAP(map, i) & TRANSITION_PASSED)
#define IS_FAILED(map, i)	(MAP(map, i) & TRANSITION_FAILED)

static void *ff1(void *map)
{
	char __tls_data[10] = "1122334455";
	pid_t pid;
	int status;

	memcpy(tls_data, __tls_data, sizeof(tls_data));

	pid = test_fork();
	if (pid < 0) {
		exit(1);
	} else if (pid == 0) {
		SET_CREATED(map, 4);
		while (1) {
			int ret = 0;
			pthread_mutex_lock(&mtx);
			if (memcmp(tls_data, __tls_data, sizeof(tls_data)))
				ret = 1;
			pthread_mutex_unlock(&mtx);
			if (ret) {
				if (IS_STARTED(map, 4)) {
					SET_FAILED(map, 4);
					exit(4);
				}
			} else {
				if (IS_STARTED(map, 4)) {
					SET_PASSED(map, 4);
					exit(4);
				}
			}
			sleep(1);
		}
	}

	SET_CREATED(map, 5);
	while (1) {
		int ret = 0;
		pthread_mutex_lock(&mtx);
		if (memcmp(tls_data, __tls_data, sizeof(tls_data)))
			ret = 1;
		pthread_mutex_unlock(&mtx);
		if (ret) {
			if (IS_STARTED(map, 5))
				SET_FAILED(map, 5);
		} else {
				SET_PASSED(map, 5);
		}
		if (IS_STARTED(map, 5))
			break;
		sleep(1);
	}

	test_msg("Waiting for %d\n", pid);
	waitpid(pid, &status, P_ALL);

	return NULL;
}

static void *f1(void *map)
{
	char __tls_data[10] = "3122131212";
	pthread_t th;
	pid_t pid;
	int status;

	memcpy(tls_data, __tls_data, sizeof(tls_data));

	if (pthread_create(&th, NULL, &ff1, map))
		perror("Cant create thread");

	pid = test_fork();
	if (pid < 0) {
		fail("Failed to test_fork()\n");
		exit(1);
	} else if (pid == 0) {
		SET_CREATED(map, 2);
		while (1) {
			int ret = 0;
			pthread_mutex_lock(&mtx);
			if (memcmp(tls_data, __tls_data, sizeof(tls_data)))
				ret = 1;
			pthread_mutex_unlock(&mtx);
			if (ret) {
				if (IS_STARTED(map, 2)) {
					SET_FAILED(map, 2);
					exit(2);
				}
			} else {
				if (IS_STARTED(map, 2)) {
					SET_PASSED(map, 2);
					exit(2);
				}
			}
			sleep(1);
		}
	}

	SET_CREATED(map, 3);
	while (1) {
		int ret = 0;
		pthread_mutex_lock(&mtx);
		if (memcmp(tls_data, __tls_data, sizeof(tls_data)))
			ret = 1;
		pthread_mutex_unlock(&mtx);
		if (ret) {
			if (IS_STARTED(map, 3))
				SET_FAILED(map, 3);
		} else {
				SET_PASSED(map, 3);
		}
		if (IS_STARTED(map, 3))
			break;
		sleep(1);
	}

	pthread_join(th, NULL);
	test_msg("Waiting for %d\n", pid);
	waitpid(pid, &status, P_ALL);

	return NULL;
}

static void *f2(void *map)
{
	char __tls_data[10] = "wasdfrdgdc";
	pid_t pid;
	int status;

	memcpy(tls_data, __tls_data, sizeof(tls_data));

	pid = test_fork();
	if (pid < 0) {
		fail("Failed to test_fork()\n");
		exit(1);
	} else if (pid == 0) {
		SET_CREATED(map, 0);
		while (1) {
			int ret = 0;
			pthread_mutex_lock(&mtx);
			if (memcmp(tls_data, __tls_data, sizeof(tls_data)))
				ret = 1;
			pthread_mutex_unlock(&mtx);
			if (ret) {
				if (IS_STARTED(map, 0)) {
					SET_FAILED(map, 0);
					exit(0);
				}
			} else {
				if (IS_STARTED(map, 0)) {
					SET_PASSED(map, 0);
					exit(0);
				}
			}
			sleep(1);
		}
	}

	SET_CREATED(map, 1);
	while (1) {
		int ret = 0;
		pthread_mutex_lock(&mtx);
		if (memcmp(tls_data, __tls_data, sizeof(tls_data)))
			ret = 1;
		pthread_mutex_unlock(&mtx);
		if (ret) {
			if (IS_STARTED(map, 1))
				SET_FAILED(map, 1);
		} else {
				SET_PASSED(map, 1);
		}
		if (IS_STARTED(map, 1))
			break;
		sleep(1);
	}

	test_msg("Waiting for %d\n", pid);
	waitpid(pid, &status, P_ALL);

	return NULL;
}

int main(int argc, char *argv[])
{
	pthread_t th1, th2;
	int rc1, rc2;
	void *map;

	test_init(argc, argv);

	test_msg("%s pid %d\n", argv[0], getpid());
	map = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (map == MAP_FAILED) {
		fail("Can't map");
		exit(1);
	}

	rc1 = pthread_create(&th1, NULL, &f1, map);
	rc2 = pthread_create(&th2, NULL, &f2, map);

	if (rc1 | rc2) {
		fail("Can't pthread_create");
		exit(1);
	}

	test_msg("Waiting until all threads are created\n");
	for (;;) {
		if (IS_CREATED(map, 0) &&
		    IS_CREATED(map, 1) &&
		    IS_CREATED(map, 2) &&
		    IS_CREATED(map, 3) &&
		    IS_CREATED(map, 4) &&
		    IS_CREATED(map, 5))
			break;
		sleep(1);
	}

	SET_STARTED(map, 0);
	SET_STARTED(map, 1);
	SET_STARTED(map, 2);
	SET_STARTED(map, 3);
	SET_STARTED(map, 4);
	SET_STARTED(map, 5);

	test_daemon();
	test_waitsig();

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
