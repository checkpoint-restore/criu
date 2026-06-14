#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/inotify.h>
#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc = "Check inotify C/R on overlayfs mounts";
const char *test_author = "Ankit Mahajan <ankimaha-sys@users.noreply.github.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define BUFF_SIZE ((sizeof(struct inotify_event) + PATH_MAX))

#define LOWER	"lower"
#define UPPER	"upper"
#define WORK	"work"
#define MERGED	"merged"

int main(int argc, char *argv[])
{
	char lower[PATH_MAX], upper[PATH_MAX], work[PATH_MAX], merged[PATH_MAX];
	char test_file[PATH_MAX];
	char buf[BUFF_SIZE];
	char opts[PATH_MAX * 4];
	int fd, wd, len, real_fd;

	test_init(argc, argv);

	if (strlen(dirname) > PATH_MAX - 64) {
		pr_perror("dirname too long");
		return 1;
	}

	sprintf(lower, "%s/%s", dirname, LOWER);
	sprintf(upper, "%s/%s", dirname, UPPER);
	sprintf(work, "%s/%s", dirname, WORK);
	sprintf(merged, "%s/%s", dirname, MERGED);

	if (mkdir(dirname, 0755) && errno != EEXIST) {
		pr_perror("Can't create %s", dirname);
		return 1;
	}
	if (mkdir(lower, 0755)) {
		pr_perror("Can't create %s", lower);
		return 1;
	}
	if (mkdir(upper, 0755)) {
		pr_perror("Can't create %s", upper);
		return 1;
	}
	if (mkdir(work, 0755)) {
		pr_perror("Can't create %s", work);
		return 1;
	}
	if (mkdir(merged, 0755)) {
		pr_perror("Can't create %s", merged);
		return 1;
	}

	/* Create a test file in the lower layer */
	sprintf(test_file, "%s/testfile", lower);
	real_fd = open(test_file, O_CREAT | O_WRONLY, 0644);
	if (real_fd < 0) {
		pr_perror("Can't create %s", test_file);
		return 1;
	}
	close(real_fd);

	/* Mount overlayfs */
	sprintf(opts, "lowerdir=%s,upperdir=%s,workdir=%s",
		lower, upper, work);
	if (mount("overlay", merged, "overlay", 0, opts)) {
		pr_perror("Can't mount overlayfs");
		return 1;
	}

	/* Set up inotify watch on file inside the overlay */
	sprintf(test_file, "%s/testfile", merged);

	fd = inotify_init1(IN_NONBLOCK);
	if (fd < 0) {
		pr_perror("inotify_init1 failed");
		goto umount;
	}

	wd = inotify_add_watch(fd, test_file, IN_MODIFY | IN_ACCESS);
	if (wd < 0) {
		pr_perror("inotify_add_watch failed on %s", test_file);
		goto umount;
	}

	test_msg("Added inotify watch (wd=%d) on %s\n", wd, test_file);

	test_daemon();
	test_waitsig();

	/*
	 * After restore, verify the watch still works by triggering
	 * an event and reading it.
	 */
	real_fd = open(test_file, O_RDONLY);
	if (real_fd < 0) {
		fail("Can't open %s after restore", test_file);
		goto umount;
	}
	close(real_fd);

	len = read(fd, buf, sizeof(buf));
	if (len <= 0) {
		fail("No inotify events after restore (len=%d)", len);
		goto umount;
	}

	pass();

umount:
	close(fd);
	umount2(merged, MNT_DETACH);
	return 0;
}
