/*
 * Check that the process and thread names set via PR_SET_NAME are
 * preserved across checkpoint and restore for both main process and
 * spawned threads, verified via prctl(PR_GET_NAME) and /proc/<pid>/comm.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that PR_SET_NAME survives C/R for multiple threads";
const char *test_author	= "Mayur Galhate <galhatemayur@gmail.com>";

/* Maximum comm length supported by kernel is 16 bytes (15 chars + NUL) */
#define MAIN_NAME	"zdtm-main-15chr"
#define THREAD_NAME	"zdtm-thrd-15chr"

static int check_comm(const char *path, const char *expected)
{
	char buf[32];
	FILE *f;
	size_t len;

	f = fopen(path, "r");
	if (!f) {
		pr_perror("Can't open %s", path);
		return -1;
	}

	if (!fgets(buf, sizeof(buf), f)) {
		pr_perror("Can't read %s", path);
		fclose(f);
		return -1;
	}
	fclose(f);

	len = strlen(buf);
	if (len > 0 && buf[len - 1] == '\n')
		buf[len - 1] = '\0';

	if (strcmp(buf, expected)) {
		pr_err("%s mismatch: expected \"%s\", got \"%s\"\n",
		       path, expected, buf);
		return -1;
	}

	return 0;
}

static void *thread_fn(void *arg)
{
	char name[16];
	char path[64];
	pid_t tid;

	(void)arg;

	if (prctl(PR_SET_NAME, THREAD_NAME, 0, 0, 0)) {
		pr_perror("thread: can't set process name");
		return (void *)(uintptr_t)1;
	}

	test_waitsig();

	memset(name, 0, sizeof(name));
	if (prctl(PR_GET_NAME, name, 0, 0, 0)) {
		pr_perror("thread: can't get process name after restore");
		return (void *)(uintptr_t)1;
	}

	if (strcmp(name, THREAD_NAME)) {
		pr_err("thread: prctl name mismatch: expected \"%s\", got \"%s\"\n",
		       THREAD_NAME, name);
		return (void *)(uintptr_t)1;
	}

	tid = syscall(SYS_gettid);
	snprintf(path, sizeof(path), "/proc/self/task/%d/comm", tid);
	if (check_comm(path, THREAD_NAME))
		return (void *)(uintptr_t)1;

	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t thread;
	void *thread_ret;
	char name[16];
	int ret;

	test_init(argc, argv);

	if (prctl(PR_SET_NAME, MAIN_NAME, 0, 0, 0)) {
		pr_perror("main: can't set process name");
		return 1;
	}

	ret = pthread_create(&thread, NULL, thread_fn, NULL);
	if (ret) {
		pr_err("pthread_create: %d\n", ret);
		return 1;
	}

	test_daemon();
	test_waitsig();

	memset(name, 0, sizeof(name));
	if (prctl(PR_GET_NAME, name, 0, 0, 0)) {
		fail("main: can't get process name after restore");
		return 1;
	}

	if (strcmp(name, MAIN_NAME)) {
		fail("main: prctl name mismatch: expected \"%s\", got \"%s\"",
		     MAIN_NAME, name);
		return 1;
	}

	if (check_comm("/proc/self/comm", MAIN_NAME)) {
		fail("main: /proc/self/comm mismatch");
		return 1;
	}

	ret = pthread_join(thread, &thread_ret);
	if (ret) {
		pr_err("pthread_join: %d\n", ret);
		return 1;
	}

	if (thread_ret) {
		fail("thread comm was not preserved correctly");
		return 1;
	}

	pass();
	return 0;
}
