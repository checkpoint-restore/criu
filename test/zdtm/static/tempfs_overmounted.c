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
	if (chdir(dirname)) {
		pr_perror("chdir");
		return 1;
	}

	mkdir("a", 0777);
	mkdir("a/b", 0777);

	mount(NULL, "/", NULL, MS_PRIVATE, "");
	if (mount("none", "a/b", "tmpfs", 0, "") < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}
	if (mount("none", "a/b", "tmpfs", 0, "") < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}
	mkdir("a/b/c", 0777);
	if (mount("none", "a/b/c", "tmpfs", 0, "") < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}
	if (mount("none", "a", "tmpfs", 0, "") < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}
	if (mount("none", "a", "tmpfs", 0, "") < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}
	mkdir("a/b", 0777);
	if (mount("none", "a/b", "tmpfs", 0, "") < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (umount("a/b") || umount("a") || umount("a") || umount("a/b/c") || umount("a/b") || umount("a/b")) {
		pr_err("umount");
		return 1;
	}

	pass();
	return 0;
}
