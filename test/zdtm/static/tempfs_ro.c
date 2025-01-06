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
	if (mount("none", dirname, "tmpfs", 0, "") < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}

	snprintf(fname, sizeof(buf), "%s/test.file", dirname);
	fd = open(fname, O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		pr_perror("open failed");
		goto err;
	}

	if (write(fd, TEST_WORD, sizeof(TEST_WORD)) != sizeof(TEST_WORD)) {
		pr_perror("write() failed");
		goto err;
	}
	close(fd);

	if (mount(NULL, dirname, "tmpfs", MS_REMOUNT | MS_RDONLY, NULL) < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}

	test_daemon();
	test_waitsig();

	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		pr_perror("open failed");
		goto err;
	}

	buf[sizeof(TEST_WORD) + 1] = '\0';
	if (read(fd, buf, sizeof(TEST_WORD)) != sizeof(TEST_WORD)) {
		fail("Read failed");
		goto err;
	}
	close(fd);

	if (strcmp(buf, TEST_WORD)) {
		fail("File corrupted");
		goto err;
	}

	pass();
	ret = 0;
err:
	umount2(dirname, MNT_DETACH);
	rmdir(dirname);
	return ret;
}
