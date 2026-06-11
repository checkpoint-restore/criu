#include <sched.h>
#include <unistd.h>
#include <limits.h>
#include <ftw.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/inotify.h>

#include "zdtmtst.h"

const char *test_doc = "Check inotify C/R on overlayfs";
const char *test_author = "CRIU contributors";

char *dirname = "inotify_overlayfs.test";
TEST_OPTION(dirname, string, "directory name", 1);

#define BUFF_SIZE ((sizeof(struct inotify_event) + PATH_MAX))
#define TEST_FNAME "testfile"

#define OVL_DIR_SUFFIX "zdtm_inotify_ovl.XXXXXX"

static int rm_entry(const char *path, const struct stat *st,
		    int flag, struct FTW *ftw)
{
	return remove(path);
}

/*
 * Clean up overlay backing dirs matching the zdtm_inotify_ovl prefix
 * in the given directory.  Called at setup to remove leftovers from
 * previous runs.  Post-test cleanup is handled by
 * inotify_overlayfs.hook (--clean).
 */
static void cleanup_stale_ovl_dirs(const char *parent)
{
	DIR *d;
	struct dirent *de;
	char path[PATH_MAX];

	d = opendir(parent);
	if (!d)
		return;

	while ((de = readdir(d)) != NULL) {
		if (strncmp(de->d_name, "zdtm_inotify_ovl.",
			    strlen("zdtm_inotify_ovl.")) != 0)
			continue;
		snprintf(path, sizeof(path), "%s/%s", parent, de->d_name);
		nftw(path, rm_entry, 16, FTW_DEPTH | FTW_PHYS);
	}
	closedir(d);
}

int main(int argc, char *argv[])
{
	char merged[PATH_MAX], watch_path[PATH_MAX];
	char buf[BUFF_SIZE];
	int inotify_fd, wd, fd, dir_fd;
	char *zdtm_newns = getenv("ZDTM_NEWNS");
	cleanup_free char *cwd = NULL;

	cwd = get_current_dir_name();
	snprintf(merged, sizeof(merged), "%s/%s", cwd, dirname);

	if (zdtm_newns && !strcmp(zdtm_newns, "1")) {
		char ovl_dir[PATH_MAX - 2];
		char ovl_lower[PATH_MAX], ovl_upper[PATH_MAX];
		char ovl_work[PATH_MAX];
		char ovl_mnt[] = "/tmp/zdtm_ino_mnt.XXXXXX";
		char opts[3 * PATH_MAX + 32];

		/*
		 * Phase 1: running before namespace creation.
		 *
		 * Overlay backing dirs (lower/upper/work) are placed
		 * in cwd so they live on a real filesystem — tmpfs
		 * does not support overlayfs upperdir on all kernels.
		 *
		 * The overlay is mounted at a temporary directory
		 * under /tmp, which is outside ZDTM_ROOT and will
		 * not be visible after pivot_root.  After unshare
		 * we bind-mount it into the test directory; the bind
		 * creates a shared/master relationship that
		 * --external mnt[]:s can detect.
		 */
		cleanup_stale_ovl_dirs(cwd);

		snprintf(ovl_dir, sizeof(ovl_dir), "%s/" OVL_DIR_SUFFIX, cwd);
		if (!mkdtemp(ovl_dir)) {
			pr_perror("Can't create overlay tmpdir");
			return 1;
		}

		snprintf(ovl_lower, sizeof(ovl_lower), "%s/l", ovl_dir);
		snprintf(ovl_upper, sizeof(ovl_upper), "%s/u", ovl_dir);
		snprintf(ovl_work, sizeof(ovl_work), "%s/w", ovl_dir);

		if (mkdir(ovl_lower, 0700) < 0) {
			pr_perror("Can't mkdir %s", ovl_lower);
			return 1;
		}
		if (mkdir(ovl_upper, 0700) < 0) {
			pr_perror("Can't mkdir %s", ovl_upper);
			return 1;
		}
		if (mkdir(ovl_work, 0700) < 0) {
			pr_perror("Can't mkdir %s", ovl_work);
			return 1;
		}

		/* Create a test file in the lower layer */
		dir_fd = openat(AT_FDCWD, ovl_lower, O_RDONLY | O_DIRECTORY);
		if (dir_fd < 0) {
			pr_perror("Can't open lower dir %s", ovl_lower);
			return 1;
		}
		fd = openat(dir_fd, TEST_FNAME, O_CREAT | O_WRONLY, 0644);
		close(dir_fd);
		if (fd < 0) {
			pr_perror("Can't create test file in lower");
			return 1;
		}
		close(fd);

		/*
		 * Mount overlay at a path outside ZDTM_ROOT so it
		 * does not appear in mountinfo after pivot_root.
		 */
		if (!mkdtemp(ovl_mnt)) {
			pr_perror("Can't create overlay mount dir");
			return 1;
		}
		snprintf(opts, sizeof(opts),
			 "lowerdir=%s,upperdir=%s,workdir=%s",
			 ovl_lower, ovl_upper, ovl_work);

		if (mount("overlay", ovl_mnt, "overlay", 0, opts) < 0) {
			pr_perror("Can't mount overlayfs at %s", ovl_mnt);
			return 1;
		}

		if (unshare(CLONE_NEWNS)) {
			pr_perror("unshare");
			return 1;
		}

		/* Bind-mount into test directory inside new mntns */
		if (mkdir(merged, 0700) < 0) {
			pr_perror("Can't mkdir %s", merged);
			return 1;
		}
		if (mount(ovl_mnt, merged, NULL, MS_BIND, NULL) < 0) {
			pr_perror("Can't bind-mount overlay to %s", merged);
			return 1;
		}
	}

	/*
	 * test_init handles ZDTM_NEWNS internally:
	 *  "1" -> ns_create() re-execs with "2" (never returns)
	 *  "2" -> ns_init() forks, child continues
	 *  unset -> normal execution
	 */
	test_init(argc, argv);

	snprintf(watch_path, sizeof(watch_path),
		 "%s/" TEST_FNAME, dirname);

	inotify_fd = inotify_init1(IN_NONBLOCK);
	if (inotify_fd < 0) {
		pr_perror("inotify_init1 failed");
		return 1;
	}

	wd = inotify_add_watch(inotify_fd, watch_path, IN_OPEN);
	if (wd < 0) {
		pr_perror("inotify_add_watch failed for %s", watch_path);
		close(inotify_fd);
		return 1;
	}

	test_daemon();
	test_waitsig();

	/* After restore, trigger an inotify event */
	fd = open(watch_path, O_RDONLY);
	if (fd < 0) {
		fail("Can't open %s after restore", watch_path);
		close(inotify_fd);
		return 1;
	}
	close(fd);

	/* Check that we got the event */
	memset(buf, 0, sizeof(buf));
	if (read(inotify_fd, buf, sizeof(buf)) <= 0) {
		fail("No inotify events after restore");
		close(inotify_fd);
		return 1;
	}

	close(inotify_fd);
	pass();
	return 0;
}
