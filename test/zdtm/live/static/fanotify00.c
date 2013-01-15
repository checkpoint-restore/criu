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
#include <linux/fanotify.h>

#include "zdtmtst.h"

#ifdef __x86_64__
# define __NR_fanotify_init	300
# define __NR_fanotify_mark	301
#else
# define __NR_fanotify_init	338
# define __NR_fanotify_mark	339
#endif

const char *test_doc	= "Check for fanotify delivery";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

const char fanotify_path[] = "fanotify-del-after-cr";

#define BUFF_SIZE ((sizeof(struct inotify_event) + PATH_MAX))

static int fanotify_init(unsigned int flags, unsigned int event_f_flags)
{
	return syscall(__NR_fanotify_init, flags, event_f_flags);
}

static int fanotify_mark(int fanotify_fd, unsigned int flags, unsigned long mask,
			 int dfd, const char *pathname)
{
	return syscall(__NR_fanotify_mark, fanotify_fd, flags, mask, dfd, pathname);
}

int main (int argc, char *argv[])
{
	char buf[BUFF_SIZE];
	int fa_fd, fd, del_after;

	test_init(argc, argv);

	fa_fd = fanotify_init(FAN_NONBLOCK | O_RDONLY | O_LARGEFILE |
			      FAN_CLASS_NOTIF | FAN_UNLIMITED_QUEUE,
			      0);
	if (fa_fd < 0) {
		err("fanotify_init failed\n");
		exit(1);
	}

	del_after = open(fanotify_path, O_CREAT | O_TRUNC);
	if (del_after < 0) {
		err("open failed\n");
		exit(1);
	}

	if (fanotify_mark(fa_fd, FAN_MARK_ADD,
			  FAN_MODIFY | FAN_ACCESS | FAN_OPEN | FAN_CLOSE,
			  AT_FDCWD, fanotify_path)) {
		err("fanotify_mark failed\n");
		exit(1);
	}

	if (fanotify_mark(fa_fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
			  FAN_ONDIR | FAN_OPEN | FAN_CLOSE,
			  AT_FDCWD, "/")) {
		err("fanotify_mark failed\n");
		exit(1);
	}

	if (fanotify_mark(fa_fd, FAN_MARK_ADD | FAN_MARK_MOUNT |
			  FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORED_SURV_MODIFY,
			  FAN_MODIFY | FAN_ACCESS,
			  AT_FDCWD, "/")) {
		err("fanotify_mark failed\n");
		exit(1);
	}

	test_daemon();
	test_waitsig();

	fd = open("/", O_RDONLY);
	close(fd);

	fd = open(fanotify_path, O_RDWR);
	close(fd);

	if (unlink(fanotify_path)) {
		fail("can't unlink %s\n", fanotify_path);
		exit(1);
	}

	if (read(fa_fd, buf, sizeof(buf)) <= 0) {
		fail("No events in fanotify queue\n");
		exit(1);
	}

	pass();

	return 0;
}
