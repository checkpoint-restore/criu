#include <sched.h>
#include <sys/mount.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc = "Test c/r of tracefs";
const char *test_author = "Tycho Andersen <tycho.andersen@canonical.com>";

char *dirname = "mnt_tracefs.test";
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	char dst[PATH_MAX];

	if (strcmp(getenv("ZDTM_NEWNS"), "1"))
		goto test;

	if (unshare(CLONE_NEWNS)) {
		pr_perror("unshare");
		return 1;
	}

	sprintf(dst, "%s/%s", get_current_dir_name(), dirname);
	if (mkdir(dst, 755) < 0) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount("/sys/kernel/debug", dst, NULL, MS_BIND | MS_REC, NULL)) {
		rmdir(dst);
		pr_perror("mount");
		return 1;
	}

	/* trigger the tracefs mount */
	strcat(dst, "/tracing/README");
	if (access(dst, F_OK) < 0) {
		umount(dst);
		rmdir(dst);
		pr_perror("access");
		return 1;
	}

test:
	test_init(argc, argv);

	test_daemon();
	test_waitsig();

	sprintf(dst, "%s/%s/tracing/README", get_current_dir_name(), dirname);

	/* EACCES is what we expect, since users can't actually /see/ this
	 * filesystem, but CRIU needs to know how to remount it, so the restore
	 * should succeed
	 */
	if (access(dst, F_OK) < 0 && errno != EACCES) {
		fail("couldn't access tracefs at %s", dst);
		return 1;
	}

	pass();
	return 0;
}
