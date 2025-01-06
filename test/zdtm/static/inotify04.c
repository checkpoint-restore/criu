#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/inotify.h>

#include "zdtmtst.h"

const char *test_doc = "Check inotify does not have trash in queue after c/r";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define TEST_FILE "inotify-testfile"

#define BUFF_SIZE ((sizeof(struct inotify_event) + PATH_MAX))

static int inotify_read_events(int inotify_fd, unsigned int *n)
{
	struct inotify_event *event;
	char buf[BUFF_SIZE * 8];
	int ret, off;

	*n = 0;

	while (1) {
		ret = read(inotify_fd, buf, sizeof(buf));
		if (ret < 0) {
			if (errno != EAGAIN) {
				pr_perror("Can't read inotify queue");
				return -1;
			} else {
				ret = 0;
				break;
			}
		} else if (ret == 0)
			break;

		for (off = 0; off < ret; (*n)++, off += sizeof(*event) + event->len) {
			event = (void *)(buf + off);
			test_msg("Event %#10x\n", event->mask);
		}
	}

	test_msg("Read %u events\n", *n);
	return ret;
}

int main(int argc, char *argv[])
{
	unsigned int mask = IN_ALL_EVENTS;
	char test_file_path[PATH_MAX];
	int fd, ifd, ifd2, ret;
	unsigned int n;

	test_init(argc, argv);

	if (mkdir(dirname, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) {
		pr_perror("Can't create directory %s", dirname);
		return 1;
	}

	snprintf(test_file_path, sizeof(test_file_path), "%s/%s", dirname, TEST_FILE);

	fd = open(test_file_path, O_CREAT, 0644);
	if (fd < 0) {
		pr_perror("Failed to create %s", test_file_path);
		return 1;
	}
	close(fd);

	ifd = inotify_init1(IN_NONBLOCK);
	if (ifd < 0) {
		pr_perror("Failed inotify_init");
		return 1;
	}

	ifd2 = inotify_init1(IN_NONBLOCK);
	if (ifd2 < 0) {
		pr_perror("Failed inotify_init");
		return 1;
	}

	if (inotify_add_watch(ifd, test_file_path, mask) < 0) {
		pr_perror("Failed inotify_add_watch");
		return 1;
	}

	if (inotify_add_watch(ifd2, test_file_path, mask) < 0) {
		pr_perror("Failed inotify_add_watch");
		return 1;
	}

	test_daemon();
	test_waitsig();

	ret = inotify_read_events(ifd, &n);
	if (ret < 0) {
		fail("Failed to read inotify events");
		return 1;
	} else if (n != 0) {
		fail("Found %d unexpected inotify events", n);
		return 1;
	}

	ret = inotify_read_events(ifd, &n);
	if (ret < 0) {
		fail("Failed to read inotify events");
		return 1;
	} else if (n != 0) {
		fail("Found %d unexpected inotify events", n);
		return 1;
	}

	close(ifd);
	close(ifd2);
	unlink(test_file_path);
	pass();

	return 0;
}
