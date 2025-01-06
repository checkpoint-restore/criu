#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc = "Check external mount from host's rootfs";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname = "mnt_root_ext.test";
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	char *root, testdir[PATH_MAX], nstestdir[PATH_MAX];
	char *zdtm_newns = getenv("ZDTM_NEWNS");
	char tmp[] = "/.zdtm_root_ext.tmp";

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

	/* Prepare directories in criu root */
	mkdir(tmp, 0755);

	/* Make criu's mntns root mount shared */
	if (mount(NULL, "/", NULL, MS_SHARED, NULL)) {
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
	 * Make mounts in temporary mntns slave, to prevent propagation to criu mntns
	 */
	if (mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL)) {
		pr_perror("make rslave");
		return 1;
	}

	/*
	 * Populate to the tests root host's rootfs subdir
	 */
	if (mount(tmp, testdir, NULL, MS_BIND, NULL)) {
		pr_perror("bind");
		return 1;
	}
test:
	test_init(argc, argv);

	/*
	 * Make "external" mount to be slave
	 */
	sprintf(nstestdir, "/%s", dirname);
	if (mount(NULL, nstestdir, NULL, MS_SLAVE, NULL)) {
		pr_perror("make slave");
		return 1;
	}

	test_daemon();
	test_waitsig();

	pass();

	return 0;
}
