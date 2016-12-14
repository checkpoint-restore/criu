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

const char *test_doc	= "Check shared non-root bind-mounts with different shared groups";
const char *test_author	= "Andrew Vagin <avagin@gmail.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);


int main(int argc, char **argv)
{
	test_init(argc, argv);

	if (mkdir(dirname, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (chdir(dirname))
		return 1;

	if (mkdir("1", 0700) || mkdir("2", 0700) || mkdir("3", 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mkdir("A", 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mkdir("B", 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount("1", "1", NULL, MS_BIND, NULL) ||
	    mount(NULL, "1", NULL, MS_PRIVATE, NULL) ||
	    mount(NULL, "1", NULL, MS_SHARED, NULL)) {
		pr_perror("mount");
		return 1;
	}

	if (mount("1", "A", NULL, MS_BIND, NULL) ||
	    mount(NULL, "A", NULL, MS_PRIVATE, NULL) ||
	    mount(NULL, "A", NULL, MS_SHARED, NULL)) {
		pr_perror("mount");
		return 1;
	}

	if (mount("1", "B", NULL, MS_BIND, NULL) ||
	    mount(NULL, "B", NULL, MS_SLAVE, NULL)) {
		pr_perror("mount");
		return 1;
	}

	if (mkdir("1/D", 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount("1/D", "2", NULL, MS_BIND, NULL)) {
		pr_perror("mount");
		return 1;
	}

	if (mount("1", "3", NULL, MS_BIND, NULL)) {
		pr_perror("mount");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (mkdir("1/D/test", 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount("zdtm_shared", "1/D/test", "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}

	if (mount(NULL, "3", NULL, MS_PRIVATE, NULL)) {
		pr_perror("mount");
		return 1;
	}

	if (umount("B/D/test")) {
		pr_perror("umount");
		return 1;
	}
	if (umount("2/test")) {
		pr_perror("umount");
		return 1;
	}
	if (umount("3/D/test")) {
		pr_perror("umount");
		return 1;
	}

	pass();

	return 0;
}
