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
char test_files[2][128] = {TDIR"/zdtm-test", TDIR"/zdtm-test1"};

#define BUFF_SIZE ((sizeof(struct inotify_event) + PATH_MAX))

int main (int argc, char *argv[])
{
	char buf[BUFF_SIZE];
	int fd, wd, i;

	test_init(argc, argv);

	for (i = 0; i < 2; i++) {
		unlink(test_files[i]);
		if (creat(test_files[i], 0600) < 0) {
			pr_perror("Can't make test file");
			exit(1);
		}
	}

	fd = inotify_init1(IN_NONBLOCK);
	if (fd < 0) {
		pr_perror("inotify_init failed");
		goto err;
	}

	for (i = 0; i < 2; i++) {
		wd = inotify_add_watch(fd, test_files[i], IN_OPEN);
		if (wd < 0) {
			pr_perror("inotify_add_watch failed");
			goto err;
		}
	}

	test_daemon();
	test_waitsig();

	for (i = 0; i < 2; i++) {
		memset(buf, 0, sizeof(buf));
		wd = open(test_files[i], O_RDONLY);
		if (read(fd, buf, sizeof(buf)) <= 0) {
			fail("No events in queue");
			goto err;
		}
	}

	close(wd);
	close(fd);
	for (i = 0; i < 2; i++)
		unlink(test_files[i]);
	pass();
	return 0;
err:
	for (i = 0; i < 2; i++)
		unlink(test_files[i]);
	return 1;
}
