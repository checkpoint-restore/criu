#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include "zdtmtst.h"

const char *test_doc	= "Check tmpfs mount";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define TEST_WORD	"testtest"

int main(int argc, char **argv)
{
	int fd, ret = 1;
	char buf[1024];

	test_init(argc, argv);

	mkdir(dirname, 0700);
	if (mount("none", dirname, "tmpfs", 0, "") < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}

	snprintf(buf, sizeof(buf), "%s/test", dirname);
	fd = open(buf, O_RDWR | O_CREAT);
	if (fd < 0) {
		err("open failed");
		goto outum;
	}

	if (write(fd, TEST_WORD, sizeof(TEST_WORD)) != sizeof(TEST_WORD)) {
		err("write() failed");
		goto outuc;
	}

	test_daemon();
	test_waitsig();

	if (lseek(fd, 0, SEEK_SET) < 0) {
		fail("Seek failed");
		goto outuc;
	}

	buf[sizeof(TEST_WORD) + 1] = '\0';
	if (read(fd, buf, sizeof(TEST_WORD)) != sizeof(TEST_WORD)) {
		fail("Read failed");
		goto outuc;
	}

	if (strcmp(buf, TEST_WORD)) {
		fail("File corrupted");
		goto outuc;
	}

	pass();
	ret = 0;
outuc:
	close(fd);
outum:
	umount(dirname);
	rmdir(dirname);
	return ret;
}
