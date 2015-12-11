#define _GNU_SOURCE

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
#include <signal.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/prctl.h>

#include "zdtmtst.h"

const char *test_doc	= "Check for inotify file-handles storm";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

static int num_of_handles(int fd)
{
	char path[64];
	char buf[512];
	int ret = 0;
	FILE *f;

	snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
	f = fopen(path, "r");
	if (!f) {
		pr_err("Can't open %s", path);
		return -1;
	}

	while (fgets(buf, sizeof(buf), f)) {
		if (memcmp(buf, "inotify ", 8))
			continue;
		ret++;
	}

	fclose(f);
	return ret;
}

int main (int argc, char *argv[])
{
	const unsigned int mask = IN_DELETE | IN_CLOSE_WRITE | IN_DELETE_SELF | IN_CREATE;
	const int nr_dirs = 64;
	char temp[nr_dirs][16];
	char path[PATH_MAX];
	int fd, i;

	test_init(argc, argv);

	if (mkdir(dirname, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) {
		pr_err("Can't create directory %s", dirname);
		exit(1);
	}

	fd = inotify_init1(IN_NONBLOCK);
	if (fd < 0) {
		pr_err("inotify_init failed");
		exit(1);
	}

	for (i = 0; i < nr_dirs; i++) {
		snprintf(temp[i], sizeof(temp[0]), "d.%03d", i);
		snprintf(path, sizeof(path), "%s/%s", dirname, temp[i]);
		if (mkdir(path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) {
			pr_err("Can't create %s", path);
			exit(1);
		}

		if (inotify_add_watch(fd, path, mask) < 0) {
			pr_err("inotify_add_watch failed on %s", path);
			exit(1);
		}
	}

	test_daemon();
	test_waitsig();

	i = num_of_handles(fd);
	close(fd);

	if (i < nr_dirs)
		fail("Expected %d handles but got %d", nr_dirs, i);
	else
		pass();

	return 0;
}
