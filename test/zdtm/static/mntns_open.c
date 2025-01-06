#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sched.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <limits.h>

#include "zdtmtst.h"

#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000
#endif

const char *test_doc = "Check that mnt_id is respected";
const char *test_author = "Pavel Emelianov <xemul@parallels.com>";

#define MPTS_FILE "F"
char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);
char fpath[PATH_MAX];

#define NS_STACK_SIZE 4096
/* All arguments should be above stack, because it grows down */
struct ns_exec_args {
	char stack[NS_STACK_SIZE] __stack_aligned__;
	char stack_ptr[0];
	int fd;
};

#define AWK_OK	 13
#define AWK_FAIL 42

static int get_mntid(int fd)
{
	char str[256];
	int mnt_id = -1;
	FILE *f;

	snprintf(str, sizeof(str), "/proc/self/fdinfo/%d", fd);
	f = fopen(str, "r");
	if (!f) {
		pr_perror("Can't open %s to parse", str);
		return -1;
	}
	while (fgets(str, sizeof(str), f)) {
		if (sscanf(str, "mnt_id: %d", &mnt_id) == 1)
			break;
	}

	fclose(f);
	return mnt_id;
}

task_waiter_t t;

int ns_child(void *_arg)
{
	struct ns_exec_args *args = _arg;
	int fd2;
	int id1, id2;

	fd2 = open(fpath, O_RDWR);
	task_waiter_complete(&t, 1);
	test_waitsig();

	id1 = get_mntid(args->fd);
	id2 = get_mntid(fd2);

	test_msg("%d %d", id1, id2);

	if (id1 < 0 || id2 < 0)
		exit(1);
	if (id1 > 0 && id1 != id2)
		exit(AWK_OK);
	else
		exit(AWK_FAIL);
}

int main(int argc, char **argv)
{
	struct ns_exec_args args;
	pid_t pid = -1;

	test_init(argc, argv);

	task_waiter_init(&t);

	snprintf(fpath, sizeof(fpath), "%s/%s", dirname, MPTS_FILE);
	if (mkdir(dirname, 0600) < 0) {
		fail("Can't make zdtm_sys");
		return 1;
	}

	if (getenv("ZDTM_NOSUBNS") == NULL) {
		args.fd = open(fpath, O_CREAT | O_RDWR, 0600);
		if (args.fd < 0) {
			fail("Can't open file");
			return 1;
		}

		pid = clone(ns_child, args.stack_ptr, CLONE_NEWNS | SIGCHLD, &args);
		if (pid < 0) {
			pr_perror("Unable to fork child");
			return 1;
		}

		close(args.fd);
	}

	task_waiter_wait4(&t, 1);

	test_daemon();
	test_waitsig();

	if (pid > 0) {
		int status = 1;
		kill(pid, SIGTERM);
		wait(&status);
		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status) == AWK_OK)
				pass();
			else if (WEXITSTATUS(status) == AWK_FAIL)
				fail("Mount ID not restored");
			else
				fail("Failed to check mount IDs (%d)", WEXITSTATUS(status));
		} else
			fail("Test died");
	}

	unlink(fpath);
	rmdir(dirname);
	return 0;
}
