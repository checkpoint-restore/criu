#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc = "Check overmount on shared parent works";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	char dir_a[PATH_MAX], dir_b[PATH_MAX], dir_c[PATH_MAX];
	char dir_d[PATH_MAX], dir_a_c[PATH_MAX];

	test_init(argc, argv);

	mkdir(dirname, 0700);

	if (mount(dirname, dirname, NULL, MS_BIND, NULL)) {
		pr_perror("Unable to self bind mount %s", dirname);
		return 1;
	}

	if (mount(NULL, dirname, NULL, MS_SHARED, NULL)) {
		pr_perror("Unable to make shared mount %s", dirname);
		return 1;
	}

	ssprintf(dir_a, "%s/a", dirname);
	ssprintf(dir_d, "%s/d", dirname);
	mkdir(dir_a, 0700);
	mkdir(dir_d, 0700);

	ssprintf(dir_b, "%s/b", dir_a);
	ssprintf(dir_c, "%s/c", dir_b);
	mkdir(dir_b, 0700);
	mkdir(dir_c, 0700);

	if (mount(dir_b, dir_a, NULL, MS_BIND, NULL)) {
		pr_perror("Unable to bind mount %s to %s", dir_b, dir_a);
		return 1;
	}

	ssprintf(dir_a_c, "%s/c", dir_a);

	if (mount(dir_d, dir_a_c, NULL, MS_BIND, NULL)) {
		pr_perror("Unable to bind mount %s to %s", dir_d, dir_a_c);
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (umount(dir_a_c)) {
		pr_perror("Unable to umount %s", dir_a_c);
		return 1;
	}

	if (umount(dir_a)) {
		pr_perror("Unable to umount %s", dir_a);
		return 1;
	}

	pass();
	return 0;
}
