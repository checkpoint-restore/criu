#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <limits.h>

#include "zdtmtst.h"

const char *test_doc	= "Check two mounts in the same directory";
const char *test_author	= "Andrew Vagin <avagin@parallels.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);


int main(int argc, char **argv)
{
	char d1[PATH_MAX], d2[PATH_MAX], f1[PATH_MAX], f2[PATH_MAX];
	struct stat st;

	test_init(argc, argv);

	snprintf(d1, sizeof(d1), "%s/1/", dirname);
	snprintf(d2, sizeof(d2), "%s/2/", dirname);

	if (mkdir(dirname, 0700) ||
	    mkdir(d1, 0777) ||
	    mkdir(d2, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount("zdtm_d1", d1, "sysfs", 0, NULL) ||
	    mount(NULL, d1, NULL, MS_SHARED, NULL) ||
            mount(d1, d2, NULL, MS_BIND, NULL) ||
            mount(NULL, d2, NULL, MS_SLAVE, NULL)) {
		pr_perror("mount");
		return 1;
	}

	snprintf(f1, sizeof(f1), "%s/devices", d1);
	snprintf(f2, sizeof(f2), "%s/devices", d2);

	if (mount("zdtm_d1", d1, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (umount(d1)) {
		pr_perror("umount");
		return 1;
	}

	if (stat(f1, &st) || stat(f2, &st)) {
		pr_perror("stat");
		return 1;
	}

	pass();

	return 0;
}
