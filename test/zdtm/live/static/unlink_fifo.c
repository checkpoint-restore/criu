#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that we can migrate with a named pipe "
			"open and then unlinked";
const char *test_author	= "Roman Kagan <rkagan@parallels.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

int main(int argc, char **argv)
{
	int fd;
	mode_t mode = S_IFIFO | 0700;

	test_init(argc, argv);

	if (mknod(filename, mode, 0)) {
		pr_perror("can't make fifo \"%s\"", filename);
		exit(1);
	}

	fd = open(filename, O_RDWR);
	if (fd < 0) {
		pr_perror("can't open %s", filename);
		return 1;
	}

	if (unlink(filename) < 0) {
		pr_perror("can't unlink %s", filename);
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (close(fd) < 0) {
		fail("can't close %s: %m", filename);
		return 1;
	}

	pass();
	return 0;
}
