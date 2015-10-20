#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that we can migrate with a named pipe, "
			"opened in WRONLY mode and then unlinked";
char *filename;
TEST_OPTION(filename, string, "file name", 1);

int main(int argc, char **argv)
{
	int fd, fd1;
	mode_t mode = S_IFIFO | 0600;

	test_init(argc, argv);

	if (mknod(filename, mode, 0)) {
		pr_perror("can't make fifo \"%s\"", filename);
		exit(1);
	}

	fd = open(filename, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		pr_perror("open(%s, O_RDONLY | O_NONBLOCK) Failed",
			filename);
		return 1;
	}

	fd1 = open(filename, O_WRONLY);
	if (fd1 < 0) {
		pr_perror("open(%s, O_WRONLY) Failed", filename);
		return 1;
	}

	if (unlink(filename) < 0) {
		pr_perror("can't unlink %s", filename);
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (close(fd) < 0) {
		fail("can't close (O_RDONLY | O_NONBLOCK) %s: %m", filename);
		return 1;
	}

	if (close(fd1) < 0) {
		fail("can't close (O_WRONLY) %s: %m", filename);
		return 1;
	}

	pass();
	return 0;
}
