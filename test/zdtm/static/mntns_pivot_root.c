#include <sched.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

#include "zdtmtst.h"
#include "lock.h"

const char *test_doc = "Check nested mntns with different root";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname = "mntns_pivot_root.test";
TEST_OPTION(dirname, string, "directory name", 1);

char *source = "mntns_pivot_root";

enum {
	TEST_INIT = 0,
	TEST_CHILD,
	TEST_CHECK,
	TEST_EXIT,
	EMERGENCY_ABORT,
};

futex_t *futex;

static int sys_pivot_root(const char *new_root, const char *put_old)
{
	return syscall(SYS_pivot_root, new_root, put_old);
}

#define BUF_SIZE 4096

static int child(void)
{
	char *put_root = "put_root";
	char *testfile = "testfile";
	int fd;

	if (unshare(CLONE_NEWNS)) {
		pr_perror("unshare");
		goto err;
	}
	/*
	 * Setup new root
	 */
	mkdir(dirname, 0755);

	if (mount(source, dirname, "tmpfs", 0, NULL)) {
		pr_perror("mount tmpfs");
		goto err;
	}

	if (mount(NULL, dirname, NULL, MS_PRIVATE, NULL)) {
		pr_perror("make private");
		goto err;
	}

	if (chdir(dirname)) {
		pr_perror("chdir");
		goto err;
	}

	mkdir(put_root, 0755);

	if (sys_pivot_root(".", put_root)) {
		pr_perror("pivot_root");
		goto err;
	}

	if (umount2(put_root, MNT_DETACH)) {
		pr_perror("umount2");
		goto err;
	}

	fd = open(testfile, O_RDWR | O_CREAT | O_EXCL, 0666);
	if (fd < 0) {
		pr_perror("open");
		goto err;
	}
	close(fd);

#ifdef MNTNS_PIVOT_ROOT_RO
	/*
	 * Hack to make cr_pivot_root work on readonly mntns root,
	 * normally nested containers have /tmp directory
	 */
	mkdir("tmp", 0755);
	/*
	 * Make superblock readonly
	 */
	if (mount(NULL, "/", NULL, MS_REMOUNT | MS_RDONLY, NULL)) {
		pr_perror("remount_ro");
		goto err;
	}
#endif

	futex_set_and_wake(futex, TEST_CHILD);
	futex_wait_while_lt(futex, TEST_CHECK);

	if (access(testfile, F_OK)) {
		pr_perror("access");
		goto err;
	}

#ifdef MNTNS_PIVOT_ROOT_RO
	/*
	 * Check superblock readonly
	 */
	fd = open(testfile, O_WRONLY);
	if (fd >= 0) {
		pr_err("Open on readonly superblock should fail\n");
		close(fd);
		goto err;
	} else if (errno != EROFS) {
		pr_perror("open write");
		goto err;
	}
#endif

	futex_set_and_wake(futex, TEST_EXIT);
	return 0;
err:
	futex_set_and_wake(futex, EMERGENCY_ABORT);
	return 1;
}

int main(int argc, char **argv)
{
	int pid;

	test_init(argc, argv);

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
