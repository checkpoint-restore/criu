#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc	= "Check tmpfs mount";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define TEST_WORD	"testtest"
#define TEST_WORD2	"TESTTEST"

int main(int argc, char **argv)
{
	int fd, fdo, ret = 1;
	char buf[1024], fname[PATH_MAX], overmount[PATH_MAX];

	test_init(argc, argv);

	mkdir(dirname, 0700);
	if (mount("none", dirname, "tmpfs", 0, "") < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}

	snprintf(fname, sizeof(buf), "%s/test.file", dirname);
	fdo = open(fname, O_RDWR | O_CREAT, 0644);
	if (fdo < 0) {
		err("open failed");
		goto err;
	}

	if (write(fdo, TEST_WORD, sizeof(TEST_WORD)) != sizeof(TEST_WORD)) {
		err("write() failed");
		goto err;
	}

	snprintf(overmount, sizeof(buf), "%s/test", dirname);
	mkdir(overmount, 0700);

	snprintf(fname, sizeof(buf), "%s/test.file", overmount);
	fd = open(fname, O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		err("open failed");
		goto err;
	}

	if (write(fd, TEST_WORD2, sizeof(TEST_WORD2)) != sizeof(TEST_WORD2)) {
		err("write() failed");
		goto err;
	}
	close(fd);

	if (mount("none", overmount, "tmpfs", 0, "") < 0) {
		fail("Can't mount tmpfs");
		goto err;
	}

	test_daemon();
	test_waitsig();

	if (umount(overmount) < 0) {
		fail("Can't mount tmpfs");
		goto err;
	}

	lseek(fdo, 0, SEEK_SET);
	buf[sizeof(TEST_WORD) + 1] = '\0';
	if (read(fdo, buf, sizeof(TEST_WORD)) != sizeof(TEST_WORD)) {
		fail("Read failed");
		goto err;
	}
	close(fdo);

	if (strcmp(buf, TEST_WORD)) {
		fail("File corrupted");
		goto err;
	}

	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		err("open failed");
		goto err;
	}

	buf[sizeof(TEST_WORD2) + 1] = '\0';
	if (read(fd, buf, sizeof(TEST_WORD2)) != sizeof(TEST_WORD2)) {
		fail("Read failed");
		goto err;
	}
	close(fd);

	if (strcmp(buf, TEST_WORD2)) {
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
