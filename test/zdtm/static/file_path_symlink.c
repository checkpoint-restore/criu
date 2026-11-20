#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check that restore fails if a path component of an opened file "
		       "is replaced with a symlink between dump and restore";
const char *test_author = "Andrei Vagin <avagin@google.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define TEST_STRING "Hello, world!"

/*
 * The test opens dirname/dir/file. Before restore, the hook replaces
 * dirname/dir with a symlink to dirname/dir.real, which contains the
 * same file. Paths of dumped files never contain symlinks, so criu has to
 * refuse to follow it and restore has to fail.
 */
int main(int argc, char **argv)
{
	char path[PATH_MAX], buf[sizeof(TEST_STRING)];
	int fd;

	test_init(argc, argv);

	if (mkdir(dirname, 0700)) {
		pr_perror("Can't create %s", dirname);
		return 1;
	}

	snprintf(path, sizeof(path), "%s/dir", dirname);
	if (mkdir(path, 0700)) {
		pr_perror("Can't create %s", path);
		return 1;
	}

	snprintf(path, sizeof(path), "%s/dir/file", dirname);
	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		pr_perror("Can't open %s", path);
		return 1;
	}

	if (write(fd, TEST_STRING, sizeof(TEST_STRING)) != sizeof(TEST_STRING)) {
		pr_perror("Can't write to %s", path);
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (pread(fd, buf, sizeof(buf), 0) != sizeof(buf)) {
		fail("Can't read from %s", path);
		return 1;
	}

	if (memcmp(buf, TEST_STRING, sizeof(buf))) {
		fail("File content mismatch");
		return 1;
	}

	pass();
	return 0;
}
