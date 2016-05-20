#include <sys/mount.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc	= "Test c/r of tracefs";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

char *dirname = "mnt_tracefs.test";
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char ** argv)
{
	char dst[PATH_MAX], *root;
	int status;
	pid_t pid;

	root = getenv("ZDTM_ROOT");
	if (root == NULL) {
		pr_perror("root");
		return 1;
	}

	sprintf(dst, "%s/debugfs", getenv("ZDTM_ROOT"));

	if (strcmp(getenv("ZDTM_NEWNS"), "1"))
		goto test;

	pid = fork();
	if (pid < 0)
		return 1;
	if (pid == 0) {
		test_ext_init(argc, argv);

		mkdir(dst, 755);
		if (mount("/sys/kernel/debug", dst, NULL, MS_BIND, NULL)) {
			pr_perror("mount");
			return 1;
		}
		return 0;
	}

	wait(&status);
	if (status != 0)
		return 1;

test:
	test_init(argc, argv);

	test_daemon();
	test_waitsig();


	pass();

	return 0;
}

