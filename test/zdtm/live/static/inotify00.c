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
#include <dirent.h>

#include "zdtmtst.h"

const char *test_doc	= "Check for inotify delivery";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define TEST_FILE	"inotify-removed"
#define TEST_LINK	"inotify-hardlink"

#define BUFF_SIZE ((sizeof(struct inotify_event) + PATH_MAX))

static void decode_event_mask(char *buf, size_t size, unsigned int mask)
{
	static const char *names[32] = {
		[ 0]	= "IN_ACCESS",
		[ 1]	= "IN_MODIFY",
		[ 2]	= "IN_ATTRIB",
		[ 3]	= "IN_CLOSE_WRITE",
		[ 4]	= "IN_CLOSE_NOWRITE",
		[ 5]	= "IN_OPEN",
		[ 6]	= "IN_MOVED_FROM",
		[ 7]	= "IN_MOVED_TO",
		[ 8]	= "IN_CREATE",
		[ 9]	= "IN_DELETE",
		[10]	= "IN_DELETE_SELF",
		[11]	= "IN_MOVE_SELF",

		[13]	= "IN_UNMOUNT",
		[14]	= "IN_Q_OVERFLOW",
		[15]	= "IN_IGNORED",

		[24]	= "IN_ONLYDIR",
		[25]	= "IN_DONT_FOLLOW",
		[26]	= "IN_EXCL_UNLINK",

		[29]	= "IN_MASK_ADD",
		[30]	= "IN_ISDIR",
		[31]	= "IN_ONESHOT",
	};

	size_t i, j;

	memset(buf, 0, size);
	for (i = 0, j = 0; i < 32 && j < size; i++) {
		if (!(mask & (1u << i)))
			continue;
		if (j)
			j += snprintf(&buf[j], size - j, " | %s", names[i]);
		else
			j += snprintf(&buf[j], size - j, "%s", names[i]);
	}
}

static int inotify_read_events(char *prefix, int inotify_fd, unsigned int *expected)
{
	struct inotify_event *event;
	char buf[BUFF_SIZE * 8];
	int ret, off, n = 0;

	while (1) {
		ret = read(inotify_fd, buf, sizeof(buf));
		if (ret < 0) {
			if (errno != EAGAIN) {
				err("Can't read inotify queue");
				return -1;
			} else {
				ret = 0;
				goto out;
			}
		} else if (ret == 0)
			break;

		for (off = 0; off < ret; n++, off += sizeof(*event) + event->len) {
			char emask[128];

			event = (void *)(buf + off);
			decode_event_mask(emask, sizeof(emask), event->mask);
			test_msg("\t%-16s: event %#10x -> %s\n",
				 prefix, event->mask, emask);
			if (expected)
				*expected &= ~event->mask;
		}
	}

out:
	test_msg("\t%-16s: read %2d events\n", prefix, n);
	return ret;
}

int main (int argc, char *argv[])
{
	unsigned int mask = IN_DELETE | IN_CLOSE_WRITE | IN_DELETE_SELF | IN_CREATE;
	char test_file_path[PATH_MAX];
	int fd, real_fd;
	unsigned int emask;

	test_init(argc, argv);

	fd = inotify_init1(IN_NONBLOCK);
	if (fd < 0) {
		err("inotify_init failed");
		exit(1);
	}

	if (mkdir(dirname, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) {
		err("Can't create directory %s", dirname);
		exit(1);
	}

	snprintf(test_file_path, sizeof(test_file_path), "%s/%s", dirname, TEST_FILE);

	real_fd = open(test_file_path, O_CREAT | O_TRUNC | O_RDWR, 0644);
	if (real_fd < 0) {
		err("Can't create %s", test_file_path);
		exit(1);
	}

	if (inotify_add_watch(fd, dirname, mask) < 0) {
		err("inotify_add_watch failed");
		exit(1);
	}

	if (inotify_add_watch(fd, test_file_path, mask) < 0) {
		err("inotify_add_watch failed");
		exit(1);
	}

	/*
	 * At this moment we have a file inside testing
	 * directory and a hardlink to it. The file and
	 * hardlink are opened.
	 */

	if (unlink(test_file_path)) {
		err("can't unlink %s\n", test_file_path);
		exit(1);
	}

	emask = IN_DELETE;
	inotify_read_events("unlink 02", fd, &emask);
	if (emask) {
		char emask_bits[128];
		decode_event_mask(emask_bits, sizeof(emask_bits), emask);
		err("Unhandled events in emask %#x -> %s",
		    emask, emask_bits);
		exit(1);
	}

	test_daemon();
	test_waitsig();

	close(real_fd);

	emask = IN_CLOSE_WRITE;
	inotify_read_events("after", fd, &emask);
	if (emask) {
		char emask_bits[128];
		decode_event_mask(emask_bits, sizeof(emask_bits), emask);
		fail("Unhandled events in emask %#x -> %s",
		    emask, emask_bits);
		return 1;
	}

	real_fd = open(test_file_path, O_CREAT | O_TRUNC | O_RDWR, 0644);
	if (real_fd < 0) {
		err("Can't create %s", test_file_path);
		exit(1);
	}
	close(real_fd);

	emask = IN_CREATE | IN_CLOSE_WRITE;
	inotify_read_events("after2", fd, &emask);
	if (emask) {
		char emask_bits[128];
		decode_event_mask(emask_bits, sizeof(emask_bits), emask);
		fail("Unhandled events in emask %#x -> %s",
		    emask, emask_bits);
		return 1;
	}

	pass();

	return 0;
}
