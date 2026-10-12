#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check that fresh mount remount flag failures are not ignored";
const char *test_author = "Deepak Anand <deepakanand1300@gmail.com>";

#define TEST_DIR "rootless_mntns_remount_flags.test"

static int check_separate_mount(void)
{
	struct stat parent, mounted;

	if (stat(".", &parent)) {
		pr_perror("stat .");
		return -1;
	}

	if (stat(TEST_DIR, &mounted)) {
		pr_perror("stat %s", TEST_DIR);
		return -1;
	}

	if (parent.st_dev == mounted.st_dev) {
		fail("%s is not a separate mount", TEST_DIR);
		return -1;
	}

	return 0;
}

static int check_strictatime(void)
{
	char line[4096], mountpoint[256], opts[256];
	char target[PATH_MAX];
	FILE *f;
	int ret = -1;

	if (!realpath(TEST_DIR, target)) {
		pr_perror("realpath %s", TEST_DIR);
		return -1;
	}

	f = fopen("/proc/self/mountinfo", "r");
	if (!f) {
		pr_perror("open mountinfo");
		return -1;
	}

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%*s %*s %*s %*s %255s %255s", mountpoint, opts) != 2)
			continue;
		if (strcmp(mountpoint, target))
			continue;

		if (strstr(opts, "relatime") || strstr(opts, "noatime")) {
			fail("%s does not have strict atime flags: %s", target, opts);
			goto out;
		}

		ret = 0;
		goto out;
	}

	fail("%s not found in mountinfo", target);
out:
	fclose(f);
	return ret;
}

int main(int argc, char **argv)
{
	int ret = 1;

	test_init(argc, argv);

	if (mkdir(TEST_DIR, 0755) && errno != EEXIST) {
		pr_perror("mkdir %s", TEST_DIR);
		return 1;
	}

	if (mount("none", TEST_DIR, "tmpfs", MS_STRICTATIME, "mode=0755")) {
		pr_perror("mount %s", TEST_DIR);
		goto out_rmdir;
	}

	if (check_separate_mount())
		goto out_umount;
	if (check_strictatime())
		goto out_umount;

	test_daemon();
	test_waitsig();

	if (check_separate_mount())
		goto out_umount;
	if (check_strictatime())
		goto out_umount;

	pass();
	ret = 0;

out_umount:
	if (umount(TEST_DIR)) {
		pr_perror("umount %s", TEST_DIR);
		ret = 1;
	}
out_rmdir:
	if (rmdir(TEST_DIR)) {
		pr_perror("rmdir %s", TEST_DIR);
		ret = 1;
	}

	return ret;
}
