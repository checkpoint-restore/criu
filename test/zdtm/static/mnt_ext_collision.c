#include <sched.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/limits.h>

#include "zdtmtst.h"
#include "lock.h"

const char *test_doc = "Check external mount mountpoint collide with different mount in nested mntns";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname = "mnt_ext_collision.test";
TEST_OPTION(dirname, string, "directory name", 1);

char *source = "zdtm_ext_collision";
char *source2 = "zdtm_ext_collision_2";

enum {
	TEST_INIT = 0,
	TEST_CHILD,
	TEST_CHECK,
	TEST_EXIT,
	EMERGENCY_ABORT,
};

futex_t *futex;

#define BUF_SIZE 4096

static int child(void)
{
	char dst[PATH_MAX], dst_file[PATH_MAX];
	int fd;

	if (unshare(CLONE_NEWNS)) {
		pr_perror("unshare");
		goto err;
	}

	/*
	 * Umount external mount copy
	 */
	sprintf(dst, "/%s/dst", dirname);
	if (umount(dst)) {
		pr_perror("umount");
		goto err;
	}

	/*
	 * Mount tmpfs in its place
	 */
	if (mount(source2, dst, "tmpfs", 0, NULL)) {
		pr_perror("mount tmpfs");
		goto err;
	}

	sprintf(dst_file, "/%s/dst/file", dirname);
	fd = open(dst_file, O_RDWR | O_CREAT | O_EXCL, 0666);
	if (fd < 0) {
		pr_perror("open");
		goto err;
	}
	close(fd);

	futex_set_and_wake(futex, TEST_CHILD);
	futex_wait_while_lt(futex, TEST_CHECK);

	if (access(dst_file, F_OK)) {
		pr_perror("access");
		goto err;
	}

	futex_set_and_wake(futex, TEST_EXIT);
	return 0;
err:
	futex_set_and_wake(futex, EMERGENCY_ABORT);
	return 1;
}

int main(int argc, char **argv)
{
	char *root, testdir[PATH_MAX];
	char lckd[PATH_MAX], dst[PATH_MAX];
	char *tmp = "/tmp/zdtm_ext_collision.tmp";
	char *zdtm_newns = getenv("ZDTM_NEWNS");
	int pid;

	root = getenv("ZDTM_ROOT");
	if (root == NULL) {
		pr_perror("root");
		return 1;
	}

	if (!zdtm_newns) {
		pr_perror("ZDTM_NEWNS is not set");
		return 1;
	} else if (strcmp(zdtm_newns, "1")) {
		goto test;
	}

	/* Prepare directories in test root */
	sprintf(testdir, "%s/%s", root, dirname);
	mkdir(testdir, 0755);

	sprintf(lckd, "%s/%s/lckd", root, dirname);
	mkdir(lckd, 0755);
	sprintf(dst, "%s/%s/dst", root, dirname);
	mkdir(dst, 0755);

	/* Prepare mount in criu root */
	mkdir(tmp, 0755);
	if (mount(source, tmp, "tmpfs", 0, NULL)) {
		pr_perror("mount tmpfs");
		return 1;
	}
	if (mount(NULL, tmp, NULL, MS_PRIVATE, NULL)) {
		pr_perror("make private");
		return 1;
	}

	/*
	 * Create temporary mntns, next mounts will not show up in criu mntns
	 */
	if (unshare(CLONE_NEWNS)) {
		pr_perror("unshare");
		return 1;
	}

	/*
	 * Populate external mount to the tests mntns root
	 * (in uns flavour this would become locked)
	 */
	if (mount(tmp, lckd, NULL, MS_BIND, NULL)) {
		pr_perror("bind");
		return 1;
	}
test:
	test_init(argc, argv);

	/*
	 * Hack to create unlocked external mount without pivot_root+bind thing
	 */
	sprintf(lckd, "/%s/lckd", dirname);
	sprintf(dst, "/%s/dst", dirname);
	if (mount(lckd, dst, NULL, MS_BIND, NULL)) {
		pr_perror("bind");
		return 1;
	}

	/*
	 * Setup futex for processes synchronization
	 */
	futex = mmap(NULL, sizeof(futex), PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (futex == MAP_FAILED) {
		pr_perror("mmap");
		return 1;
	}
	futex_init(futex);

	/*
	 * Fork child which would have nested mntns
	 */
	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		return 1;
	} else if (pid == 0) {
		exit(child());
	}

	futex_wait_while_lt(futex, TEST_CHILD);
	if (futex_get(futex) == EMERGENCY_ABORT) {
		pr_err("Fail in child\n");
		return 1;
	}

	test_daemon();
	test_waitsig();

	futex_set_and_wake(futex, TEST_CHECK);
	futex_wait_while_lt(futex, TEST_EXIT);
	if (futex_get(futex) == EMERGENCY_ABORT) {
		fail("Fail in child on check stage");
		return 1;
	}

	waitpid(pid, NULL, 0);
	pass();
	return 0;
}
