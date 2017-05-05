#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sched.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <limits.h>
#include <dirent.h>

#include "zdtmtst.h"
#include "lock.h"
/*
	parent (pid_ns1, user_ns1)
	  |
	  v
	child  (pid_ns2, user_ns2)

	pid_ns1 (of user_ns1)
	  |
	  v
	pid_ns2 (of user_ns2)

	user_ns1
	  |
	  v
	user_ns2
*/

const char *test_doc	= "Check that CLONE_NEWPID|CLONE_NEWUSER|CLONE_NEWNET task restores right";
const char *test_author	= "Kirill Tkhai <ktkhai@virtuozzo.com>";

enum {
	FUTEX_INITIALIZED = 0,
	CHILD_PREPARED,
	POST_RESTORE_CHECKS,
};

futex_t *futex;

int child_fn(void *unused)
{
	pid_t pid;

	pid = getpid();
	futex_set_and_wake(futex, CHILD_PREPARED);
	futex_wait_while_lt(futex, POST_RESTORE_CHECKS);
	return pid == getpid() ? 0 : 1;
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

int __get_ns_id(int fd, unsigned int *id)
{
	struct stat st;
	if (fstat(fd, &st) < 0) {
		pr_perror("fstat() kaput");
		return 1;
	}
	*id = st.st_ino;
	return 0;
}

int get_ns_id(pid_t pid, const char *str, unsigned int *id)
{
	char buf[PATH_MAX];
	int fd, ret;
	sprintf(buf, "/proc/%d/ns/%s", pid, str);
	fd = open(buf, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", buf);
		return -1;
	}
	ret = __get_ns_id(fd, id);
	close(fd);
	return ret;
}
int main(int argc, char **argv)
{
	char stack[128] __stack_aligned__;
	unsigned int id, c_id;
	int status;
	pid_t pid;

	test_init(argc, argv);
	futex = mmap(NULL, sizeof(*futex), PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (futex == MAP_FAILED) {
		fail("mmap futex\n");
		return 1;
	}
	futex_init(futex);

	pid = clone(child_fn, stack + sizeof(stack), CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET, NULL);
	if (pid < 0) {
		fail("clone");
		return 1;
	}

	if (write_map(pid, "uid_map") || write_map(pid, "gid_map")) {
		fail("write map");
		goto err;
	}

	futex_wait_while_lt(futex, CHILD_PREPARED);

	test_daemon();
	test_waitsig();

	if (get_ns_id(getpid(), "pid", &id) || get_ns_id(pid, "pid", &c_id))
		goto err;

	if (id == c_id) {
		fail("pid namespaces are equal");
		goto err;
	}

	if (get_ns_id(getpid(), "user", &id) || get_ns_id(pid, "user", &c_id))
		goto err;

	if (id == c_id) {
		fail("user namespaces are equal");
		goto err;
	}

	futex_set_and_wake(futex, POST_RESTORE_CHECKS);

	if (wait(&status) != pid || !WIFEXITED(status) || WEXITSTATUS(status)) {
		fail("pid: status=%d\n", WEXITSTATUS(status));
		goto err;
	}

	pass();
	return 0;
err:
	futex_set_and_wake(futex, POST_RESTORE_CHECKS);
	wait(&status);
	return 1;
}
