/*
 * A simple testee program with threads
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "zdtmtst.h"

#define gettid()	pthread_self()

const char *test_doc	= "Check if /proc/self/exe points to same location after restore\n";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org";

int main(int argc, char *argv[])
{
	char path_before[PATH_MAX];
	char path_after[PATH_MAX];

	test_init(argc, argv);

	test_msg("%s pid %d\n", argv[0], getpid());
	if (readlink("/proc/self/exe", path_before, sizeof(path_before)) < 0) {
		err("Can't read selflink\n");
		fail();
		exit(1);
	}


	test_daemon();
	test_waitsig();

	if (readlink("/proc/self/exe", path_after, sizeof(path_after)) < 0) {
		err("Can't read selflink\n");
		fail();
		exit(1);
	}

	if (!strcmp(path_before, path_after))
		pass();
	else
		fail();

	return 0;
}
