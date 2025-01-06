#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc = "Check read-only tmpfs mount";
const char *test_author = "Andrew Vagin <avagin@openvz.org>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define TEST_WORD "testtest"

int main(int argc, char **argv)
{
	int fd, ret = 1;
	char buf[1024], fname[PATH_MAX];

	test_init(argc, argv);

	mkdir(dirname, 0700);
	if (mount("none", dirname, "tmpfs", MS_RDONLY, "") < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}

	snprintf(fname, sizeof(buf), "%s/test.file", dirname);

	test_daemon();
	test_waitsig();

	fd = open(fname, O_RDWR | O_CREAT, 0777);
	if (fd >= 0 || errno != EROFS) {
		pr_perror("open failed -> %d", fd);
		goto err;
	}

	pass();
	ret = 0;
err:
	umount2(dirname, MNT_DETACH);
	rmdir(dirname);
	return ret;
}
