#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc	= "Check enabled file systems (--enable-fs)";
const char *test_author	= "Andrei Vagin <avagin@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	char fname[PATH_MAX];

	test_init(argc, argv);

	mkdir(dirname, 0777);

	if (mount("zdtm_nfsd", dirname, "nfsd", 0, NULL) == -1) {
		pr_perror("mount");
		return -1;
	}

	snprintf(fname, sizeof(fname), "%s/exports", dirname);

	test_daemon();
	test_waitsig();

	if (access(fname, F_OK))
		fail();

	pass();

	return 0;
}
