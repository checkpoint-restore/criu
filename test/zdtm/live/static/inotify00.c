#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc	= "Check for inotify delivery";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

const char path[] = "inotify-removed";

#define BUFF_SIZE ((sizeof(struct inotify_event) + PATH_MAX))

int main (int argc, char *argv[])
{
	char buf[BUFF_SIZE];
	int fd, wd, deleted, wd_deleted;

	test_init(argc, argv);

	fd = inotify_init1(IN_NONBLOCK);
	if (fd < 0) {
		fail("inotify_init failed");
		exit(1);
	}

	wd  = 0;
	wd |= inotify_add_watch(fd, "/", IN_ALL_EVENTS);
	if (wd < 0) {
		fail("inotify_add_watch failed");
		exit(1);
	}

	deleted = open(path, O_CREAT | O_TRUNC);
	if (deleted < 0) {
		fail("inotify_init failed");
		exit(1);
	}

	wd_deleted = inotify_add_watch(fd, path, IN_ALL_EVENTS);
	if (wd_deleted < 0) {
		fail("inotify_add_watch failed");
		exit(1);
	}

	if (unlink(path)) {
		fail("can't unlink %s\n", path);
		exit(1);
	}

	test_daemon();
	test_waitsig();

	wd = open("/", O_RDONLY);
	if (read(fd, buf, sizeof(buf)) > 0) {
		pass();
	} else {
		fail("No events in queue");
		exit(1);
	}

	return 0;
}
