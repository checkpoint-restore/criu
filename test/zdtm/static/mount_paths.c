#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "zdtmtst.h"
#include "mountinfo.h"

const char *test_doc = "Check that special characters in paths are handled correctly";
const char *test_author = "Andrew Vagin <avagin@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define TEST_DIR "tmpfs  \t \t\\\\\t test  \t\t\\\\ \t\\ \n"
#define TEST_SRC "zdtm#src"

int main(int argc, char **argv)
{
	int ret = 1;
	char test_dir[PATH_MAX], fname[PATH_MAX];
	struct mountinfo_zdtm *mi;
	MNTNS_ZDTM(mntns);
	bool found = false;

	test_init(argc, argv);

	mkdir(dirname, 0700);

	ssprintf(test_dir, "%s/%s", dirname, TEST_DIR);
	mkdir(test_dir, 0700);

	if (mount("", test_dir, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}

	ssprintf(fname, "%s/\\\t \\\\ \\tt", test_dir);
	if (mkdir(fname, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount(TEST_SRC, fname, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (access(fname, F_OK)) {
		fail();
		goto err;
	}

	if (mntns_parse_mountinfo(&mntns)) {
		fail("Can't parse mountinfo");
		goto err;
	}

	list_for_each_entry(mi, &mntns.mountinfo_list, list)
		if (!strcmp(mi->source, TEST_SRC))
			found = true;
	if (!found) {
		fail("No mount with source %s", TEST_SRC);
		goto err;
	}

	pass();
	ret = 0;
err:
	mntns_free_all(&mntns);
	umount2(test_dir, MNT_DETACH);
	rmdir(test_dir);
	rmdir(dirname);
	return ret;
}
