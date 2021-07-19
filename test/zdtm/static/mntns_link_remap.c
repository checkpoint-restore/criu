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
#include <sys/mount.h>

#include "zdtmtst.h"

#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000
#endif

const char *test_doc = "Check ghost and link-remap files in a few mntns";
const char *test_author = "Andrew Vagin <avagin@parallels.com>";

#define MPTS_FILE "F"
char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define NS_STACK_SIZE 4096
/* All arguments should be above stack, because it grows down */
struct ns_exec_args {
	char stack[NS_STACK_SIZE] __stack_aligned__;
	char stack_ptr[0];
	int fd;
	int sync;
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

int ns_child(void *_arg)
{
	struct ns_exec_args *args = _arg;
	int fd2;
	int id1, id2;
	struct stat st1, st2;
	char lpath[PATH_MAX], fpath[PATH_MAX];

	snprintf(fpath, sizeof(fpath), "%s/1", dirname);
	if (umount(fpath)) {
		pr_perror("umount");
		return 1;
	}

	snprintf(lpath, sizeof(lpath), "%s/0/2", dirname);
	snprintf(fpath, sizeof(fpath), "%s/2", dirname);

	if (mkdir(fpath, 0600) < 0) {
		fail("Can't make zdtm_sys");
		return 1;
	}

	if (mount(lpath, fpath, NULL, MS_BIND, NULL)) {
		pr_perror("mount");
		return 1;
	}

	snprintf(fpath, sizeof(fpath), "%s/0", dirname);
	if (umount(fpath)) {
		pr_perror("umount");
		return 1;
	}

	snprintf(fpath, sizeof(fpath), "%s/2/%s", dirname, MPTS_FILE);
	fd2 = open(fpath, O_RDWR);
	if (fd2 < 0) {
		pr_perror("open");
		return -1;
	}
	close(args->sync);
	test_waitsig();

	id1 = get_mntid(args->fd);
	id2 = get_mntid(fd2);
	if (id1 < 0 || id2 < 0)
		exit(1);

	if (fstat(args->fd, &st1) || fstat(fd2, &st2)) {
		pr_perror("stat");
		exit(1);
	}

	test_msg("%d %d", id1, id2);

#ifdef ZDTM_LINK_REMAP
	if (st1.st_nlink != 1) {
#else
	if (st1.st_nlink != 0) {
#endif
		pr_perror("Wrong number of links: %lu", (long unsigned)st1.st_nlink);
		exit(1);
	}

	if (id1 > 0 && id1 != id2 && st1.st_ino == st2.st_ino)
		exit(AWK_OK);
	else
		exit(AWK_FAIL);
}

int main(int argc, char **argv)
{
	struct ns_exec_args args;
	pid_t pid = -1;
	char lpath[PATH_MAX], fpath[PATH_MAX];
	char buf[256];
	int p[2];

	test_init(argc, argv);

	if (mkdir(dirname, 0600) < 0) {
		fail("Can't make zdtm_sys");
		return 1;
	}

	if (mount("test", dirname, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}

	snprintf(fpath, sizeof(fpath), "%s/0", dirname);
	if (mkdir(fpath, 0600) < 0) {
		fail("Can't make zdtm_sys");
		return 1;
	}
	if (mount("test", fpath, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}

	snprintf(lpath, sizeof(lpath), "%s/0/1", dirname);
	if (mkdir(lpath, 0600) < 0) {
		fail("Can't make zdtm_sys");
		return 1;
	}
	snprintf(fpath, sizeof(fpath), "%s/1", dirname);
	if (mkdir(fpath, 0600) < 0) {
		fail("Can't make zdtm_sys");
		return 1;
	}
	if (mount(lpath, fpath, NULL, MS_BIND, NULL)) {
		pr_perror("mount");
		return 1;
	}
	snprintf(lpath, sizeof(lpath), "%s/0/2", dirname);
	if (mkdir(lpath, 0600) < 0) {
		fail("Can't make zdtm_sys");
		return 1;
	}

	if (pipe(p) == -1) {
		pr_perror("pipe");
		return 1;
	}

	if (getenv("ZDTM_NOSUBNS") == NULL) {
		snprintf(fpath, sizeof(fpath), "%s/1/%s", dirname, MPTS_FILE);

		args.fd = open(fpath, O_CREAT | O_RDWR, 0600);
		if (args.fd < 0) {
			fail("Can't open file");
			return 1;
		}
		snprintf(fpath, sizeof(fpath), "%s/0/1/%s", dirname, MPTS_FILE);
		snprintf(lpath, sizeof(fpath), "%s/0/2/%s", dirname, MPTS_FILE);
		if (link(fpath, lpath) == -1) {
			pr_perror("link");
			return -1;
		}
#ifdef ZDTM_LINK_REMAP
		snprintf(lpath, sizeof(fpath), "%s/0/%s", dirname, MPTS_FILE);
		if (link(fpath, lpath) == -1) {
			pr_perror("link");
			return -1;
		}
#endif
		args.sync = p[1];

		pid = clone(ns_child, args.stack_ptr, CLONE_NEWNS | SIGCHLD, &args);
		if (pid < 0) {
			pr_perror("Unable to fork child");
			return 1;
		}

		close(args.fd);
	}

	close(p[1]);
	read(p[0], buf, sizeof(buf));

	snprintf(fpath, sizeof(fpath), "%s/0/1/%s", dirname, MPTS_FILE);
	if (unlink(fpath))
		return 1;
	snprintf(fpath, sizeof(fpath), "%s/0/2/%s", dirname, MPTS_FILE);
	if (unlink(fpath))
		return 1;

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

	umount2(dirname, MNT_DETACH);
	rmdir(dirname);
	return 0;
}
