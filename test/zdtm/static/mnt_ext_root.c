#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc = "Check root external mount with \"deepper\" bind";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *source = "zdtm_ext_root";
char *dirname = "mnt_ext_root.test";
TEST_OPTION(dirname, string, "directory name", 1);

#define BUF_SIZE 4096

int main(int argc, char **argv)
{
	char *root, testdir[PATH_MAX];
	char dst[PATH_MAX], deep_bind[PATH_MAX];
	char *tmp = "/tmp/zdtm_ext_root.tmp";
	char *zdtm_newns = getenv("ZDTM_NEWNS");

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

	sprintf(dst, "%s/%s/dst", root, dirname);
	mkdir(dst, 0755);
	sprintf(deep_bind, "%s/%s/deep", root, dirname);
	mkdir(deep_bind, 0755);
	sprintf(deep_bind, "%s/%s/deep/bind", root, dirname);
	mkdir(deep_bind, 0755);

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
	 * Populate to the tests mntns root mounts
	 */
	if (mount(tmp, dst, NULL, MS_BIND, NULL)) {
		pr_perror("bind");
		return 1;
	}

	if (mount(tmp, deep_bind, NULL, MS_BIND, NULL)) {
		pr_perror("bind");
		return 1;
	}

test:
	test_init(argc, argv);

	test_daemon();
	test_waitsig();

	pass();
	return 0;
}
