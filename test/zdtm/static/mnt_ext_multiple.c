#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc = "Check multiple non-common root external mounts with same external master";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname = "mnt_ext_multiple.test";
char *source = "zdtm_ext_multiple";
char *ext_source = "zdtm_ext_multiple.ext";
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	char *root, testdir[PATH_MAX];
	char dst_a[PATH_MAX], dst_b[PATH_MAX];
	char src[PATH_MAX], src_a[PATH_MAX], src_b[PATH_MAX];
	char nsdst_a[PATH_MAX], nsdst_b[PATH_MAX];
	char *tmp = "/tmp/zdtm_ext_multiple.tmp";
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
	sprintf(dst_a, "%s/%s/dst_a", root, dirname);
	mkdir(dst_a, 0755);
	sprintf(dst_b, "%s/%s/dst_b", root, dirname);
	mkdir(dst_b, 0755);

	/* Prepare directories in criu root */
	mkdir(tmp, 0755);
	if (mount(source, tmp, "tmpfs", 0, NULL)) {
		pr_perror("mount tmpfs");
		return 1;
	}
	if (mount(NULL, tmp, NULL, MS_PRIVATE, NULL)) {
		pr_perror("make private");
		return 1;
	}
	sprintf(src, "%s/src", tmp);
	mkdir(src, 0755);

	/* Create a shared mount in criu mntns */
	if (mount(ext_source, src, "tmpfs", 0, NULL)) {
		pr_perror("mount tmpfs");
		return 1;
	}
	if (mount(NULL, src, NULL, MS_PRIVATE, NULL)) {
		pr_perror("make private");
		return 1;
	}
	if (mount(NULL, src, NULL, MS_SHARED, NULL)) {
		pr_perror("make shared");
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
	 * Populate to the tests root subdirectories of the src mount
	 */
	sprintf(src_a, "%s/src/a", tmp);
	mkdir(src_a, 0755);
	if (mount(src_a, dst_a, NULL, MS_BIND, NULL)) {
		pr_perror("bind");
		return 1;
	}
	sprintf(src_b, "%s/src/b", tmp);
	mkdir(src_b, 0755);
	if (mount(src_b, dst_b, NULL, MS_BIND, NULL)) {
		pr_perror("bind");
		return 1;
	}

test:
	test_init(argc, argv);

	/* Make "external" mounts to have external master */
	sprintf(nsdst_a, "/%s/dst_a", dirname);
	if (mount(NULL, nsdst_a, NULL, MS_SLAVE, NULL)) {
		pr_perror("make slave");
		return 1;
	}
	sprintf(nsdst_b, "/%s/dst_b", dirname);
	if (mount(NULL, nsdst_b, NULL, MS_SLAVE, NULL)) {
		pr_perror("make slave");
		return 1;
	}

	test_daemon();
	test_waitsig();

	pass();

	return 0;
}
