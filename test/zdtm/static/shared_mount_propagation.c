#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc = "Check mounts are propagated to shared mounts";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	char dir_a[PATH_MAX], dir_b[PATH_MAX], dir_c[PATH_MAX];
	char dir_d[PATH_MAX], dir_e[PATH_MAX], dir_f[PATH_MAX];
	char test_file[PATH_MAX];
	char test_bind_file1[PATH_MAX];
	char test_bind_file2[PATH_MAX];
	char test_bind_file3[PATH_MAX];
	int fd;

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
	ssprintf(dir_e, "%s/e", dirname);
	ssprintf(dir_f, "%s/f", dirname);
	mkdir(dir_a, 0700);
	mkdir(dir_d, 0700);
	mkdir(dir_e, 0700);
	mkdir(dir_f, 0700);

	ssprintf(dir_b, "%s/b", dir_a);
	ssprintf(dir_c, "%s/c", dir_b);
	mkdir(dir_b, 0700);
	mkdir(dir_c, 0700);

	if (mount(dir_a, dir_d, NULL, MS_BIND, NULL)) {
		pr_perror("Unable to bind mount %s to %s", dir_a, dir_d);
		return 1;
	}

	if (mount(dir_b, dir_e, NULL, MS_BIND, NULL)) {
		pr_perror("Unable to bind mount %s to %s", dir_b, dir_e);
		return 1;
	}

	if (mount(dir_f, dir_c, NULL, MS_BIND, NULL)) {
		pr_perror("Unable to bind mount %s to %s", dir_f, dir_c);
		return 1;
	}

	ssprintf(test_file, "%s/file", dir_f);
	fd = open(test_file, O_CREAT | O_WRONLY | O_EXCL, 0600);
	if (fd < 0) {
		pr_perror("Unable to open %s", test_file);
		return 1;
	}
	close(fd);

	test_daemon();
	test_waitsig();

	ssprintf(test_bind_file1, "%s/file", dir_c);
	ssprintf(test_bind_file2, "%s/b/c/file", dir_d);
	ssprintf(test_bind_file3, "%s/c/file", dir_e);

	if (access(test_file, F_OK)) {
		pr_perror("%s doesn't exist", test_file);
		return 1;
	}

	if (access(test_bind_file1, F_OK)) {
		pr_perror("%s doesn't exist", test_bind_file1);
		return 1;
	}

	if (access(test_bind_file2, F_OK)) {
		pr_perror("%s doesn't exist", test_bind_file2);
		return 1;
	}

	if (access(test_bind_file3, F_OK)) {
		pr_perror("%s doesn't exist", test_bind_file3);
		return 1;
	}

	if (umount(dir_c)) {
		pr_perror("Unable to umount %s", dir_c);
		return 1;
	}

	if (umount(dir_e)) {
		pr_perror("Unable to umount %s", dir_e);
		return 1;
	}

	if (umount(dir_d)) {
		pr_perror("Unable to umount %s", dir_d);
		return 1;
	}

	pass();
	return 0;
}
