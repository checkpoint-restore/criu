#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc = "Check that extended attributes of a ghost file survive checkpoint/restore";
const char *test_author = "Mallika Suri <whoismallika@gmail.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

#define USER_XATTR "user.zdtm"
#define USER_VALUE "zdtm-ghost"

int main(int argc, char **argv)
{
	char got[64];
	int fd, exit_code = 1;
	ssize_t len;

	test_init(argc, argv);

	fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("Can't open %s", filename);
		return 1;
	}

	if (unlink(filename) < 0) {
		pr_perror("Can't unlink %s", filename);
		goto err;
	}

	if (fsetxattr(fd, USER_XATTR, USER_VALUE, sizeof(USER_VALUE), 0)) {
		if (errno == EOPNOTSUPP || errno == ENOTSUP) {
			test_daemon();
			test_waitsig();
			skip("extended attributes are not supported here");
			pass();
			exit_code = 0;
			goto err;
		}
		pr_perror("Can't set %s", USER_XATTR);
		goto err;
	}

	test_daemon();
	test_waitsig();

	len = fgetxattr(fd, USER_XATTR, got, sizeof(got));
	if (len < 0) {
		fail("%s is gone from the ghost file", USER_XATTR);
		goto err;
	}

	if (len != sizeof(USER_VALUE) || memcmp(got, USER_VALUE, sizeof(USER_VALUE))) {
		fail("%s on the ghost file changed", USER_XATTR);
		goto err;
	}

	pass();
	exit_code = 0;
err:
	close(fd);
	return exit_code;
}
