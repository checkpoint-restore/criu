#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that cwd didn't change";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	char cwd0[256], cwd1[256], cwd2[256];

	test_init(argc, argv);

	if (!getcwd(cwd0, sizeof(cwd0))) {
		err("can't get cwd: %m\n");
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
		goto out;
	}

	if (strcmp(cwd1, cwd2))
		fail("%s != %s\n", cwd1, cwd2);
	else
		pass();
out:
	chdir(cwd0);	/* return to the initial dir before writing out results */
cleanup:
	chdir(cwd0);
	rmdir(dirname);
	return 0;
}
