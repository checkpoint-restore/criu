#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <pthread.h>
#include <sched.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>

#include "zdtmtst.h"
#include "lock.h"

const char *test_doc	= "Check pid_for_children of tasks and threads restore right";
const char *test_author	= "Kirill Tkhai <ktkhai@virtuozzo.com>";
/*
 * Create a child in new pid_ns; then the child creats thread and zombie.
 * Zombie is in the second created new pid_ns. Then the great parent
 * setns() to its active pid_ns. So, lets draw the table:
 *
 *	                     pid_ns vs pid_for_children_ns
 *	great parent:        equal
 *	child:               not equal
 *	child thread:        equal
 *	grand child zombie:  zombies don't have pid_for_children_ns
 */

enum {
	FUTEX_INITIALIZED = 0,
	CHILD_PREPARED,
	POST_RESTORE_CHECK,
	EMERGENCY_ABORT,
};

futex_t *futex;

enum {
	EQUAL = 0,
	NOTEQUAL,
	ERROR,
};

char *ret_names[] = {"equal", "not equal", "error"};

static int read_ns_link(const char *file_name, ino_t *id)
{
	char ns_path[128];
	struct stat st;

	sprintf(ns_path, "/proc/thread-self/ns/%s", file_name);

	if (stat(ns_path, &st)) {
		pr_perror("Unable to stat %s", ns_path);
		return -1;
	}
	*id = st.st_ino;
	return 0;
}

static int compare_pid_and_pfc(void)
{
	ino_t pid, pid_for_children;

	if (read_ns_link("pid", &pid) || read_ns_link("pid_for_children", &pid_for_children)) {
		pr_err("Can't read link\n");
		return ERROR;
	}

	if (pid != pid_for_children)
		return NOTEQUAL;
	return EQUAL;
}

static void *thread_fn(void *unused)
{
	int ret;
	futex_wait_while_lt(futex, POST_RESTORE_CHECK);
	ret = compare_pid_and_pfc();
	if (ret != EQUAL) {
		pr_err("thread: %s\n", ret_names[ret]);
		return (void *)(long)-1;
	}
	return (void *)(long)0;
}

static int child_fn(void)
{
	long thread_retval;
	pthread_t thread;
	siginfo_t infop;
	pid_t pid;
	int ret;

	ret = pthread_create(&thread, NULL, thread_fn, NULL);
	if (ret) {
		pr_perror("Can't creat thread");
		goto err;
	}

	if (unshare(CLONE_NEWPID) < 0) {
		pr_perror("Can't unshare");
		goto err;
	}

	pid = fork();
	if (pid < 0) {
		pr_perror("Can't fork");
		goto err;
	} else if (!pid)
		exit(0);

	ret = waitid(P_PID, pid, &infop, WEXITED|WNOWAIT);
	if (ret) {
		fail("Can't wait");
		goto err;
	}

	futex_set_and_wake(futex, CHILD_PREPARED);
	futex_wait_while_lt(futex, POST_RESTORE_CHECK);

	ret = pthread_join(thread, (void **)&thread_retval);
	if (ret) {
		pr_perror("Can't join thread");
		goto err;
	}

	if (thread_retval == -1) {
		pr_err("Thread finished with error\n");
		goto err;
	}

	ret = compare_pid_and_pfc();
	if (ret != NOTEQUAL) {
		pr_err("child: %s\n", ret_names[ret]);
		goto err;
	}

	return 0;
err:
	futex_set_and_wake(futex, EMERGENCY_ABORT);
	return -1;
}

int main(int argc, char **argv)
{
	int status, fd, ret;
	pid_t pid;

	test_init(argc, argv);
	futex = mmap(NULL, sizeof(*futex), PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (futex == MAP_FAILED) {
		fail("mmap futex\n");
		return 1;
	}
	futex_init(futex);

	if (unshare(CLONE_NEWPID) < 0) {
		fail("Can't unshare");
		return 1;
	}

	pid = fork();
	if (pid < 0) {
		fail("Can't fork");
		return 1;
	} else if (pid == 0)
		exit(child_fn());

	fd = open("/proc/self/ns/pid", O_RDONLY);
	if (fd < 0) {
		fail("Can't open");
		return 1;
	}

	if (setns(fd, CLONE_NEWPID) < 0) {
		fail("Can't setns");
		return 1;
	}

	futex_wait_while_lt(futex, CHILD_PREPARED);

	test_daemon();
	test_waitsig();

	ret = compare_pid_and_pfc();
	if (ret != EQUAL) {
		fail("parent: %s\n", ret_names[ret]);
		kill(pid, SIGKILL);
		return 1;
	}

	futex_set_and_wake(futex, POST_RESTORE_CHECK);

	errno = 0;
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status)) {
		fail("Can't wait or bad status: errno=%d, status=%d", errno, status);
		return 1;
	}

	pass();
	return 0;
}
