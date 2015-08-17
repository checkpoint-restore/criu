#define _GNU_SOURCE

#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>

#include <sys/mount.h>
#include <sys/stat.h>
#include <sched.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <limits.h>

#include "zdtmtst.h"

#ifndef CLONE_NEWNS
#define CLONE_NEWNS     0x00020000
#endif

const char *test_doc	= "Check the restore of deleted bindmounts";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define TEST_DIR_SRC	"test-src"
#define TEST_DIR_DST	"test-dst"

int main(int argc, char *argv[])
{
	char path_src[PATH_MAX], path_dst[PATH_MAX];

	test_init(argc, argv);

	if (mkdir(dirname, 0700)) {
		err("mkdir %s", dirname);
		exit(1);
	}

	if (mount("none", dirname, "tmpfs", MS_MGC_VAL, NULL)) {
		err("mount %s", dirname);
		return 1;
	}

	snprintf(path_src, sizeof(path_src), "%s/%s", dirname, TEST_DIR_SRC);
	snprintf(path_dst, sizeof(path_dst), "%s/%s", dirname, TEST_DIR_DST);

	rmdir(path_src);
	rmdir(path_dst);

	if (mkdir(path_src, 0700) ||
	    mkdir(path_dst, 0700)) {
		err("mkdir");
		return 1;
	}

	if (mount(path_src, path_dst, NULL, MS_BIND | MS_MGC_VAL, NULL)) {
		err("mount %s -> %s", path_src, path_dst);
		return 1;
	}

	if (rmdir(path_src)) {
		err("rmdir %s", path_src);
		return 1;
	}

	test_daemon();
	test_waitsig();

	pass();
	return 0;
}
