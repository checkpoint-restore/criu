#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that cwd didn't change";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	char cwd1[256], cwd2[256];
	int fd;

	test_init(argc, argv);

	fd = open(".", O_DIRECTORY | O_RDONLY);
	if (fd == -1) {
		err("Unable to open the current dir");
		exit(1);
	}

	if (mkdir(dirname, 0700)) {
		err("can't make directory %s: %m\n", dirname);
		exit(1);
	}

	if (chdir(dirname)) {
		err("can't change directory to %s: %m\n", dirname);
		goto cleanup;
	}

	if (!getcwd(cwd1, sizeof(cwd1))) {
		err("can't get cwd: %m\n");
		goto cleanup;
	}

	test_daemon();
	test_waitsig();

	if (!getcwd(cwd2, sizeof(cwd2))) {
		fail("can't get cwd: %m\n");
		goto cleanup;
	}

	if (strcmp(cwd1, cwd2))
		fail("%s != %s\n", cwd1, cwd2);
	else
		pass();
cleanup:
	/* return to the initial dir before writing out results */
	if (fchdir(fd)) {
		err("can't restore cwd");
		exit(1);
	}
	if (rmdir(dirname)) {
		err("can't remove directory %s: %m\n", dirname);
		exit(1);
	}
	return 0;
}
