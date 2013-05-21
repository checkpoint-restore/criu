#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <utime.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "zdtmtst.h"

const char *test_doc	= "Check for /proc/self/ns path restore";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

const char nspath[] = "/proc/self/ns/net";

int read_fd_link(int lfd, char *buf, size_t size)
{
	ssize_t ret;
	char t[32];

	snprintf(t, sizeof(t), "/proc/self/fd/%d", lfd);
	ret = readlink(t, buf, size - 1);
	if (ret < 0) {
		err("Can't read link of fd %d", lfd);
		return -1;
	}
	buf[ret] = 0;

	return 0;
}

int main(int argc, char *argv[])
{
	char path_orig[64], path_new[64];
	int fd_self, fd_new;

	test_init(argc, argv);

	memset(path_orig, 0, sizeof(path_orig));
	memset(path_new, 0, sizeof(path_new));

	fd_self = open(nspath, O_RDONLY);
	if (fd_self < 0) {
		err("Can't open %s", nspath);
		return -1;
	}

	test_daemon();
	test_waitsig();

	if (read_fd_link(fd_self, path_orig, sizeof(path_orig))) {
		err("Can't fill original path");
		return -1;
	}

	fd_new = open(nspath, O_RDONLY);
	if (fd_new < 0) {
		err("Can't open %s", nspath);
		return -1;
	}

	if (read_fd_link(fd_new, path_new, sizeof(path_new))) {
		err("Can't fill new path");
		return -1;
	}

	if (memcmp(path_orig, path_new, sizeof(path_orig))) {
		fail("Paths mismatch %s %s\n", path_orig, path_new);
		return -1;
	}

	pass();
	return 0;
}
