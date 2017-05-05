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
 * Create parent (P) and its three children (C1, C2 and C3)
 * with different pid namespaces:
 *
 *                  P (pid_ns1)
 *                 /|\
 *                / | \
 *               /  |  \
 *              /   |   \
 *             /    |    \
 * (pid_ns1) C1     C2    C3 (pid_ns1)
 *              (pid_ns2)
 *
 * where pid_ns1 is a parent of pid_ns2:
 *
 *               pid_ns1
 *                  |
 *               pid_ns2
 * Children C1, C2 and C3 created in the written order,
 * i.e. C1 has the smallest pid and C2 has the biggest
 * (so, current restorer should restore them in the same order).
 * After receiving signal check, that pid namespaces
 * restored right.
 */

#ifndef NSIO
#define NSIO    0xb7
#define NS_GET_PARENT   _IO(NSIO, 0x2)
#endif

const char *test_doc	= "Check pid namespace hierarhy restores right";
const char *test_author	= "Kirill Tkhai <ktkhai@virtuozzo.com>";

futex_t *futex;

int child(void)
{
	futex_wait_while_lt(futex, 1);
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

int get_ns_id(pid_t pid, unsigned int *id)
{
	char buf[PATH_MAX];
	int fd, ret;
	sprintf(buf, "/proc/%d/ns/pid", pid);
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
	int status, fd, p_fd, i, nr = 0;
	unsigned int id, c_id;
	char path[PATH_MAX];
	pid_t pid[3];

	test_init(argc, argv);
	futex = mmap(NULL, sizeof(*futex), PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (futex == MAP_FAILED) {
		fail("mmap futex\n");
		return 1;
	}
	futex_init(futex);

	/* Child 1 */
	pid[0] = fork();
	if (pid[0] == -1) {
		fail("fork");
		return 1;
	} else if (pid[0] == 0)
		exit(child());
	nr++;

	/* Child 2 */
	fd = open("/proc/self/ns/pid", O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't get my own pid ns");
		goto err;
	}

	if (unshare(CLONE_NEWPID) < 0) {
		pr_perror("Can't unshare");
		goto err;
	}

	pid[1] = fork();
	if (pid[1] == -1) {
		fail("fork");
		return 1;
	} else if (pid[1] == 0)
		exit(child());
	nr++;

	/* Restore pid namespace for children */
	if (setns(fd, CLONE_NEWPID) < 0) {
		pr_perror("Can't setns");
		goto err;
	}
	close(fd);

	/* Child 3 */
	pid[2] = fork();
	if (pid[2] == -1) {
		fail("fork");
		goto err;
	} else if (pid[2] == 0)
		exit(child());
	nr++;

	test_daemon();
	test_waitsig();

	if (get_ns_id(getpid(), &id))
		goto err;

	for (i = 0; i < nr; i++) {
		if (get_ns_id(pid[i], &c_id))
			goto err;
		if (i % 2 == 0) {
			if (c_id != id) {
				pr_err("Child %d has wrong pid ns\n", i);
				goto err;
			}
			continue;
		}

		if (id == c_id) {
			pr_err("Child %d has wrong pid ns\n", i);
			goto err;
		}
		/* This parent namespace of this Child's should be same to ours */
		sprintf(path, "/proc/%d/ns/pid", pid[i]);
		fd = open(path, O_RDONLY);
		if (fd < 0) {
			pr_perror("Can't open");
			goto err;
		}
		p_fd = ioctl(fd, NS_GET_PARENT);
		if (p_fd < 0)
			pr_perror("Can't get parent");
		close(fd);
		if (p_fd < 0)
			goto err;
		if (__get_ns_id(p_fd, &c_id))
			goto err;
		close(p_fd);
		if (id != c_id) {
			pr_err("Child %d has wrong pid ns hierarhy\n", i);
			goto err;
		}
	}

	futex_set_and_wake(futex, 1);

	while (nr-- > 0) {
		if (wait(&status) < 0 || WEXITSTATUS(status)) {
			fail("pid: status=%d\n", WEXITSTATUS(status));
			goto err;
		}
	}

	pass();
	return 0;
err:
	futex_set_and_wake(futex, 1);
	while (nr-- > 0)
		wait(&status);
	return 1;
}
