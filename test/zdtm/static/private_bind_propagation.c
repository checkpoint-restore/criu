#include <sys/mount.h>
#include <sys/stat.h>
#include <limits.h>

#include "zdtmtst.h"

const char *test_doc	= "Check sharing options are restored for bindmounted shared group children";
const char *test_author	= "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	char share1[PATH_MAX], share2[PATH_MAX], source[PATH_MAX];
	char child1[PATH_MAX], child2[PATH_MAX];

	test_init(argc, argv);

	if (mkdir(dirname, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount("zdtm_fs", dirname, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}

	if (mount(NULL, dirname, NULL, MS_SHARED, NULL)) {
		pr_perror("mount");
		return 1;
	}

	snprintf(share1, sizeof(share1), "%s/share1", dirname);
	if (mkdir(share1, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount("share", share1, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}

	if (mount(NULL, share1, NULL, MS_SHARED, NULL)) {
		pr_perror("mount");
		return 1;
	}

	snprintf(share2, sizeof(share2), "%s/share2", dirname);
	if (mkdir(share2, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount(share1, share2, NULL, MS_BIND, NULL)) {
		pr_perror("mount");
		return 1;
	}

	snprintf(source, sizeof(source), "%s/source", dirname);
	if (mkdir(source, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	snprintf(child1, sizeof(child1), "%s/share1/child", dirname);
	snprintf(child2, sizeof(child2), "%s/share1/child", dirname);
	if (mkdir(child1, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount(source, child1, NULL, MS_BIND, NULL)) {
		pr_perror("mount");
		return 1;
	}

	if (mount(NULL, child1, NULL, MS_PRIVATE, NULL)) {
		pr_perror("mount");
		return 1;
	}

	if (mount(NULL, child2, NULL, MS_PRIVATE, NULL)) {
		pr_perror("mount");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (umount(child1)) {
		pr_perror("Unable to umount %s", child1);
		return 1;
	}

	if (umount(share1)) {
		pr_perror("Unable to umount %s", share1);
		return 1;
	}

	if (umount(share2)) {
		pr_perror("Unable to umount %s", share2);
		return 1;
	}

	if (umount(dirname)) {
		pr_perror("Unable to umount %s", dirname);
		return 1;
	}

	pass();

	return 0;
}
