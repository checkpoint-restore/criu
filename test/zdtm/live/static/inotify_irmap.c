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

const char *test_doc	= "Check for irmap";
const char *test_author	= "Pavel Emelyanov <xemul@parallels.com>";

#define TDIR	"/etc"
#define TFIL	TDIR"/zdtm-test"

#define BUFF_SIZE ((sizeof(struct inotify_event) + PATH_MAX))

int main (int argc, char *argv[])
{
	char buf[BUFF_SIZE];
	int fd, wd;

	test_init(argc, argv);

	mkdir(TDIR, 0600);
	unlink(TFIL);
	if (creat(TFIL, 0600) < 0) {
		err("Can't make test file");
		exit(1);
	}

	fd = inotify_init1(IN_NONBLOCK);
	if (fd < 0) {
		fail("inotify_init failed");
		unlink(TFIL);
		exit(1);
	}

	wd = inotify_add_watch(fd, TFIL, IN_OPEN);
	if (wd < 0) {
		fail("inotify_add_watch failed");
		unlink(TFIL);
		exit(1);
	}

	test_daemon();
	test_waitsig();

	memset(buf, 0, sizeof(buf));
	wd = open(TFIL, O_RDONLY);
	if (read(fd, buf, sizeof(buf)) <= 0) {
		unlink(TFIL);
		fail("No events in queue");
		exit(1);
	}

	close(wd);
	close(fd);
	unlink(TFIL);
	pass();
	return 0;
}
