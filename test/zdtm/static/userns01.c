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
#include <grp.h>

#include "zdtmtst.h"
#include "lock.h"

const char *test_doc	= "Check UID and GID in unshared userns remains the same";
const char *test_author	= "Kirill Tkhai <ktkhai@virtuozzo.com>";

enum {
	FUTEX_INITIALIZED = 0,
	CHILD_CREATED,
	MAP_WRITTEN,
	XIDS_SET,
	POST_RESTORE_CHECK,
	EMERGENCY_ABORT,
};

#define CHILD_UID 50
#define CHILD_GID 53
#define UID_MAP "0 10 1\n1 100 100\n"
#define GID_MAP "0 12 1\n1 112 100\n"

gid_t gid_list[] = {3, 14, 15, 92}; /* Must be sorted */
futex_t *futex;

int write_map(pid_t pid, char *file, char *map)
{
	char path[PATH_MAX];
	int fd, ret;

	sprintf(path, "/proc/%d/%s", pid, file);
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		fail("Can't open");
		return -1;
	}
	ret = write(fd, map, strlen(map));
	if (ret != strlen(map)) {
		fail("Can't write");
		close(fd);
		return -1;
	}
	close(fd);

	return 0;
}

int compare_int(const void *a, const void *b)
{
	const int *x = a, *y = b;
	return *x - *y;
}

int child(void)
{
	gid_t gid_list2[ARRAY_SIZE(gid_list) + 1];
	int i, nr, ret;
	uid_t uid;
	gid_t gid;

	ret = unshare(CLONE_NEWUSER);
	if (ret < 0) {
		pr_perror("unshare");
		futex_set_and_wake(futex, EMERGENCY_ABORT);
		return 1;
	}

	futex_set_and_wake(futex, CHILD_CREATED);
	futex_wait_while_lt(futex, MAP_WRITTEN);

	if (setgroups(ARRAY_SIZE(gid_list), gid_list) < 0) {
		pr_perror("setgroups");
		futex_set_and_wake(futex, EMERGENCY_ABORT);
		return 2;
	}

	if (setgid(CHILD_GID) < 0) {
		pr_perror("setgid");
		futex_set_and_wake(futex, EMERGENCY_ABORT);
		return 3;
	}

	if (setuid(CHILD_UID) < 0) {
		pr_perror("setuid");
		futex_set_and_wake(futex, EMERGENCY_ABORT);
		return 4;
	}

	futex_set_and_wake(futex, XIDS_SET);
	futex_wait_while_lt(futex, POST_RESTORE_CHECK);

	uid = getuid();
	gid = getgid();
	nr = getgroups(ARRAY_SIZE(gid_list2), gid_list2);
	if (uid != CHILD_UID || gid != CHILD_GID || nr != ARRAY_SIZE(gid_list)) {
		pr_err("UID, GID or nr groups are wrong: %d %d %d\n", uid, gid, nr);
		futex_set_and_wake(futex, EMERGENCY_ABORT);
		return 5;
	}

	/* man getgroups(2) doesn't say, they are sorted */
	qsort(gid_list2, nr, sizeof(gid_t), compare_int);
	if (memcmp(gid_list, gid_list2, sizeof(gid_list)) != 0) {
		pr_err("Groups are different:\n");
		for (i = 0; i < nr; i++)
			pr_err("gid_list2[%d]=%d\n", i, gid_list2[i]);
		return 6;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int status;
	pid_t pid;

	test_init(argc, argv);
	futex = mmap(NULL, sizeof(*futex), PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (futex == MAP_FAILED) {
		fail("mmap futex\n");
		return 1;
	}
	futex_init(futex);

	pid = fork();
	if (pid == -1) {
		fail("fork");
		return 1;
	} else if (pid == 0)
		exit(child());

	futex_wait_while_lt(futex, CHILD_CREATED);

	if (write_map(pid, "uid_map", UID_MAP) < 0 ||
	    write_map(pid, "gid_map", GID_MAP) < 0) {
		fail("write map");
		goto err;
	}

	futex_set_and_wake(futex, MAP_WRITTEN);
	futex_wait_while_lt(futex, XIDS_SET);

	test_daemon();
	test_waitsig();

	futex_set_and_wake(futex, POST_RESTORE_CHECK);

	if (wait(&status) < 0 || WEXITSTATUS(status)) {
		fail("pid: status=%d\n", WEXITSTATUS(status));
		goto err;
	}

	pass();
	return 0;
err:
	futex_set_and_wake(futex, EMERGENCY_ABORT);
	wait(&status);
	return 1;
}
