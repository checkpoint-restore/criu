#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc = "Check that extended attributes of tmpfs files survive checkpoint/restore";
const char *test_author = "Mallika <whoismallika@gmail.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define XATTR_NAME  "user.zdtm"
#define XATTR_VALUE "zdtm-xattr-value"

int main(int argc, char **argv)
{
	char path[PATH_MAX], buf[64];
	int fd, ret = 1;
	ssize_t len;

	test_init(argc, argv);

	mkdir(dirname, 0700);
	if (mount("none", dirname, "tmpfs", 0, "") < 0) {
		pr_perror("Can't mount tmpfs");
		return 1;
	}

	ssprintf(path, "%s/xattr.file", dirname);
	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("Can't create %s", path);
		goto err;
	}
	close(fd);

	if (setxattr(path, XATTR_NAME, XATTR_VALUE, sizeof(XATTR_VALUE), 0)) {
		if (errno == EOPNOTSUPP) {
			test_daemon();
			test_waitsig();
			skip("extended attributes are not supported here");
			pass();
			ret = 0;
			goto err;
		}
		pr_perror("Can't set %s on %s", XATTR_NAME, path);
		goto err;
	}

	test_daemon();
	test_waitsig();

	len = getxattr(path, XATTR_NAME, buf, sizeof(buf));
	if (len < 0) {
		fail("Can't read %s back", XATTR_NAME);
		goto err;
	}

	if (len != sizeof(XATTR_VALUE) || strcmp(buf, XATTR_VALUE)) {
		fail("Wrong value of %s", XATTR_NAME);
		goto err;
	}

	pass();
	ret = 0;
err:
	umount2(dirname, MNT_DETACH);
	rmdir(dirname);
	return ret;
}
