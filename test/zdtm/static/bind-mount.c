#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc = "Check bind-mounts";
const char *test_author = "Pavel Emelianov <avagin@parallels.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	char test_dir[PATH_MAX], test_bind[PATH_MAX];
	char test_file[PATH_MAX], test_bind_file[PATH_MAX];
	int fd;

	test_init(argc, argv);

	mkdir(dirname, 0700);

	snprintf(test_dir, sizeof(test_dir), "%s/test", dirname);
	snprintf(test_bind, sizeof(test_bind), "%s/bind", dirname);
	snprintf(test_file, sizeof(test_file), "%s/test/test.file", dirname);
	snprintf(test_bind_file, sizeof(test_bind_file), "%s/bind/test.file", dirname);

	mkdir(test_dir, 0700);
	mkdir(test_bind, 0700);

	if (mount(test_dir, test_bind, NULL, MS_BIND, NULL)) {
		pr_perror("Unable to mount %s to %s", test_dir, test_bind);
		return 1;
	}

	test_daemon();
	test_waitsig();

	fd = open(test_file, O_CREAT | O_WRONLY | O_EXCL, 0600);
	if (fd < 0) {
		pr_perror("Unable to open %s", test_file);
		return 1;
	}
	close(fd);

	if (access(test_bind_file, F_OK)) {
		pr_perror("%s doesn't exist", test_bind_file);
		return 1;
	}

	if (umount(test_bind)) {
		pr_perror("Unable to umount %s", test_bind);
		return 1;
	}

	pass();
	return 0;
}
