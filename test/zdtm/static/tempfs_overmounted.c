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

int main(int argc, char **argv)
{
	test_init(argc, argv);

	mkdir(dirname, 0700);
	if (mount("none", dirname, "tmpfs", 0, "") < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}
	if (mount("none", dirname, "tmpfs", 0, "") < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}

	test_daemon();
	test_waitsig();

	pass();
	return 0;
}
