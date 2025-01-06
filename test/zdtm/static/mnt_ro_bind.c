#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <errno.h>

#include "zdtmtst.h"

const char *test_doc = "Check read-only bind-mounts";
const char *test_author = "Andrew Vagin <avagin@openvz.org>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define TEST_WORD  "testtest"
#define TEST_WORD2 "TESTTEST"

int main(int argc, char **argv)
{
	int fd, ret = 1;
	char rw_path[PATH_MAX], ro_path[PATH_MAX], rw_f[PATH_MAX], ro_f[PATH_MAX];

	test_init(argc, argv);

	snprintf(rw_path, sizeof(rw_path), "%s/rw", dirname);
	snprintf(ro_path, sizeof(ro_path), "%s/ro", dirname);
	snprintf(rw_f, sizeof(rw_f), "%s/rw/test", dirname);
	snprintf(ro_f, sizeof(ro_f), "%s/ro/test", dirname);

	mkdir(dirname, 0700);
	if (mount("none", dirname, "tmpfs", 0, "") < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}
	mkdir(rw_path, 0700);
	mkdir(ro_path, 0700);

	if (mount("zdtm_rw", rw_path, "tmpfs", 0, "") < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}

	if (mount(rw_path, ro_path, NULL, MS_BIND, NULL) < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}

	if (mount(NULL, ro_path, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}

	test_daemon();
	test_waitsig();

	fd = open(ro_f, O_CREAT | O_WRONLY, 0666);
	if (fd != -1 || errno != EROFS) {
		fail("%s is created", ro_f);
		goto err;
	}

	fd = open(rw_f, O_CREAT | O_WRONLY, 0666);
	if (fd < 0) {
		fail("Unable to create %s", rw_f);
		goto err;
	}
	close(fd);

	fd = open(ro_f, O_RDONLY);
	if (fd < 0) {
		fail("Unable to create %s", rw_f);
		goto err;
	}

	pass();
	ret = 0;
err:
	umount2(dirname, MNT_DETACH);
	rmdir(dirname);
	return ret;
}
