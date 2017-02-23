#define _GNU_SOURCE
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sched.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <limits.h>
#include <dirent.h>

#include "zdtmtst.h"
#include "lock.h"

/*
 * The test creates the following items.
 *
 *  Processes hierarhy with their namespaces (in brackets):
 *                 Parent (ns_p)
 *                /      \
 *    (ns_c1) Child1    Child2 (ns_p)
 *                        |
 *                    GrandChild (ns_gc)
 *
 *  Namespaces hierarhy:
 *         ns_p
 *           |
 *         ns_c1
 *           |
 *         ns_gc
 */
const char *test_doc	= "Check user namespaces remain the same over process tree";
const char *test_author	= "Kirill Tkhai <ktkhai@virtuozzo.com>";

enum {
	FUTEX_INITIALIZED = 0,
	CHILD1_CREATED,
	GRAND_CHILD_PID_WRITTEN,
	GRAND_CHILD_CREATED,
	GRAND_CHILD_SETUP,
	POST_RESTORE_CHECK,
	EMERGENCY_ABORT,
};

volatile pid_t *grand_child_pid;
futex_t *futex;

int get_user_ns(pid_t pid, unsigned int *ns_id)
{
	char path[PATH_MAX], buf[PATH_MAX + 1];
	int len;

	sprintf(path, "/proc/%d/ns/user", pid);
	len = readlink(path, buf, PATH_MAX);
	if (len < 0) {
		pr_perror("Can't read link %s\n", path);
		return -1;
	}

	buf[len] = '\0';
	if (sscanf(buf, "user:[%u", ns_id) < 1) {
		pr_err("Can't get id: %s\n", buf);
		return -1;
	}

	return 0;
}

int write_map(pid_t pid, char *map)
{
	char path[PATH_MAX];
	int fd, ret;

	sprintf(path, "/proc/%d/%s", pid, map);
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		fail("Can't open");
		return -1;
	}
	ret = write(fd, "0 0 1\n", 6);
	if (ret != 6) {
		fail("Can't write");
		close(fd);
		return -1;
	}
	close(fd);

	return 0;
}

/* Child1 creates its own namespace */
int child1(void)
{
	int ret;

	ret = unshare(CLONE_NEWUSER);
	if (ret < 0) {
		pr_perror("unshare");
		futex_set_and_wake(futex, EMERGENCY_ABORT);
		return 1;
	}

	futex_set_and_wake(futex, CHILD1_CREATED);
	futex_wait_while_lt(futex, GRAND_CHILD_CREATED);

	if (write_map(*grand_child_pid, "uid_map") < 0 ||
	    write_map(*grand_child_pid, "gid_map") < 0) {
		fail("write map");
		futex_set_and_wake(futex, EMERGENCY_ABORT);
		return 2;
	}

	futex_set_and_wake(futex, GRAND_CHILD_SETUP);
	futex_wait_while_lt(futex, POST_RESTORE_CHECK);

	return 0;
}

/* GrandChild switches to Child1 namespace and unshares */
int grand_child(pid_t pid1)
{
	char path[PATH_MAX];
	int fd = -1, ret;

	futex_wait_while_lt(futex, GRAND_CHILD_PID_WRITTEN);

	sprintf(path, "/proc/%d/ns/user", pid1);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("open");
		ret = 1;
		goto err;
	}

	if (setns(fd, CLONE_NEWUSER) < 0) {
		pr_perror("setns()");
		ret = 2;
		goto err;
	}
	close(fd);
	fd = -1;

	if (setuid(0) || setgid(0)) {
		pr_perror("setxids");
		ret = 3;
		goto err;
	}

	if (unshare(CLONE_NEWUSER) < 0) {
		pr_perror("unshare");
		ret = 3;
		goto err;
	}

	if (unshare(CLONE_NEWNET) < 0) {
		pr_perror("unshare");
		ret = 4;
		goto err;
	}

	futex_set_and_wake(futex, GRAND_CHILD_CREATED);
	futex_wait_while_lt(futex, POST_RESTORE_CHECK);

	return 0;
err:
	futex_set_and_wake(futex, EMERGENCY_ABORT);
	if (fd >= 0)
		close(fd);
	return ret;
}

/*
 * Child2 remains in the namespace of the parent task,
 * while its descendant GrandChild enters to Child1's
 * namespace and unshares.
 */
int child2(pid_t pid1)
{
	int status, ret;
	pid_t gc_pid;

	gc_pid = fork();
	if (gc_pid < 0) {
		pr_perror("Can't fork");
		ret = 1;
		goto err;
	} else if (gc_pid == 0)
		exit(grand_child(pid1));

	*grand_child_pid = gc_pid;
	futex_set_and_wake(futex, GRAND_CHILD_PID_WRITTEN);
	futex_wait_while_lt(futex, POST_RESTORE_CHECK);

	if (wait(&status) != *grand_child_pid) {
		pr_perror("Failed to wait grand child");
		ret = 3;
		goto err;
	}

	if (WEXITSTATUS(status)) {
		pr_err("Grand child exited with %d\n", WEXITSTATUS(status));
		ret = 4;
		goto err;
	}

	return 0;
err:
	futex_set_and_wake(futex, EMERGENCY_ABORT);
	if (*grand_child_pid > 0)
		wait(&status);
	return ret;
}


int main(int argc, char **argv)
{
	pid_t my_pid, pid1 = -1, pid2 = -1;
	unsigned int ns_p, ns_c1, ns_c2;
	int status;

	test_init(argc, argv);
	futex = mmap(NULL, sizeof(*futex) + sizeof(*grand_child_pid), PROT_WRITE | PROT_READ,
								      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	grand_child_pid = (void *)futex + sizeof(*futex);
	if (futex == MAP_FAILED) {
		fail("mmap futex\n");
		return 1;
	}
	futex_init(futex);
	my_pid = getpid();

	pid1 = fork();
	if (pid1 == -1) {
		fail("fork");
		return 1;
	} else if (pid1 == 0)
		exit(child1());

	futex_wait_while_lt(futex, CHILD1_CREATED);

	if (write_map(pid1, "uid_map") < 0 ||
	    write_map(pid1, "gid_map") < 0) {
		fail("write map");
		goto err;
	}

	pid2 = fork();
	if (pid2 == -1) {
		fail("fork");
		goto err;
	} else if (pid2 == 0)
		exit(child2(pid1));

	futex_wait_while_lt(futex, GRAND_CHILD_SETUP);
	test_daemon();
	test_waitsig();

	if (get_user_ns(my_pid, &ns_p) < 0 ||
	    get_user_ns(pid1, &ns_c1) < 0 ||
	    get_user_ns(pid2, &ns_c2) < 0) {
		fail("Can't get user ns\n");
		goto err;
	}

	if (ns_p == ns_c1 || ns_p != ns_c2) {
		fail("ns_p=%u, ns_c1=%u, ns_c2=%u\n", ns_p, ns_c1, ns_c2);
		goto err;
	}

	futex_set_and_wake(futex, POST_RESTORE_CHECK);

	errno = 0;
	if (waitpid(pid1, &status, 0) < 0 || status) {
		fail("pid1: status=%d\n", status);
		goto err;
	}

	if (waitpid(pid2, &status, 0) < 0 || status) {
		fail("pid2: status=%d\n", status);
		goto err;
	}
	pass();
	return 0;
err:
	futex_set_and_wake(futex, EMERGENCY_ABORT);
	if (pid1 > 0)
		wait(&status);
	if (pid2 > 0)
		wait(&status);
	return 1;
}
