#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that opened removed dir works";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	int fd;
	struct stat st;

	test_init(argc, argv);

	if (mkdir(dirname, 0700)) {
		pr_perror("Can't make dir");
		goto out;
	}

	fd = open(dirname, O_DIRECTORY);
	if (fd < 0) {
		pr_perror("Can't open dir");
		goto outr;
	}

	if (rmdir(dirname)) {
		pr_perror("Can't remove dir");
		goto outr;
	}

	test_daemon();
	test_waitsig();

	/*
	 * We can't compare anything with previous, since
	 * inode _will_ change, so can the device. The only
	 * reasonable thing we can do is check that the fd
	 * still points to some removed directory.
	 */
	if (fstat(fd, &st)) {
		fail("Can't stat fd\n");
		goto out;
	}

	if (!S_ISDIR(st.st_mode)) {
		fail("Fd is no longer directory\n");
		goto out;
	}

	if (st.st_nlink != 0) {
		fail("Directory is not removed\n");
		goto out;
	}

	pass();
	return 0;

outr:
	rmdir(dirname);
out:
	return 1;
}
