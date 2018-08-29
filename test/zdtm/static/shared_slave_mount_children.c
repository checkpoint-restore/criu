#include <sys/mount.h>
#include <sys/stat.h>
#include <limits.h>

#include "zdtmtst.h"

const char *test_doc	= "Check non-uniform shares restore fine";
const char *test_author	= "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	char share[PATH_MAX], slave1[PATH_MAX], slave2[PATH_MAX];
	char child[PATH_MAX];

	test_init(argc, argv);

	if (mkdir(dirname, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount("zdtm_fs", dirname, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}

	if (mount(NULL, dirname, NULL, MS_PRIVATE, NULL)) {
		pr_perror("mount");
		return 1;
	}

	snprintf(share, sizeof(share), "%s/share", dirname);
	if (mkdir(share, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount("share", share, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}

	if (mount(NULL, share, NULL, MS_SHARED, NULL)) {
		pr_perror("mount");
		return 1;
	}

	snprintf(slave1, sizeof(slave1), "%s/slave1", dirname);
	if (mkdir(slave1, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount(share, slave1, NULL, MS_BIND, NULL)) {
		pr_perror("mount");
		return 1;
	}

	if (mount(NULL, slave1, NULL, MS_SLAVE, NULL)) {
		pr_perror("mount");
		return 1;
	}

	if (mount(NULL, slave1, NULL, MS_SHARED, NULL)) {
		pr_perror("mount");
		return 1;
	}

	snprintf(slave2, sizeof(slave2), "%s/slave2", dirname);
	if (mkdir(slave2, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount(slave1, slave2, NULL, MS_BIND, NULL)) {
		pr_perror("mount");
		return 1;
	}

	snprintf(child, sizeof(child), "%s/slave1/child", dirname);
	if (mkdir(child, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount("child", child, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (umount(child)) {
		pr_perror("Unable to umount %s", child);
		return 1;
	}

	if (umount(slave2)) {
		pr_perror("Unable to umount %s", slave2);
		return 1;
	}

	if (umount(slave1)) {
		pr_perror("Unable to umount %s", slave1);
		return 1;
	}

	if (umount(share)) {
		pr_perror("Unable to umount %s", share);
		return 1;
	}

	if (umount(dirname)) {
		pr_perror("Unable to umount %s", dirname);
		return 1;
	}

	pass();

	return 0;
}
