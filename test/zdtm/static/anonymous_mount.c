#include <bits/types.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/openat2.h>
#include <linux/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <inttypes.h>
#include <sys/mount.h>

#include "zdtmtst.h"

const char *test_doc = "Check whether CRIU can c/r a fd pointing to a anonymous mount created using open_tree";
const char *test_author = "Bhavik Sachdev <b.sachdev1904@gmail.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define TEST_FILE "anonymous-mount-file"

long sys_openat2(int dirfd, const char *pathname, struct open_how *how, size_t size)
{
	return syscall(__NR_openat2, dirfd, pathname, how, size);
}

int main(int argc, char *argv[])
{
	int mntfd, fd, ret = 1;
	struct open_how how;
	char *data = "anonymous_mount.data";
	size_t len = strlen(data);
	char buf[len + 1];

	test_init(argc, argv);

	if (mkdir(dirname, 0700)) {
		pr_perror("mkdir %s", dirname);
		return 1;
	}

	/* create a mount point at dirname */
	if (mount("none", dirname, "tmpfs", 0, NULL)) {
		pr_perror("mount %s", dirname);
		return 1;
	}

	/* create a abstract (detached) clone mount of this mount */
	mntfd = open_tree(AT_FDCWD, dirname, OPEN_TREE_CLONE);
	if (mntfd < 0) {
		pr_perror("open_tree");
		return 1;
	}

	how.flags = O_CREAT | O_RDWR;
	how.mode = 0600;
	how.resolve = 0;
	fd = sys_openat2(mntfd, TEST_FILE, &how, sizeof(how));
	if (fd < 0) {
		pr_perror("openat2");
		return 1;
	}

	if (write(fd, data, len) != len) {
		pr_perror("write");
		return 1;
	}

	close(fd);

	test_daemon();
	test_waitsig();

	/* verify the contents of the file inside anonymous mount */
	how.flags = O_RDONLY;
	how.mode = 0;
	how.resolve = 0;

	fd = sys_openat2(mntfd, TEST_FILE, &how, sizeof(how));
	if (fd < 0) {
		pr_perror("open_at");
		close(mntfd);
		return 1;
	}

	if (read(fd, buf, len) != len) {
		pr_perror("read");
		goto out;
	}

	buf[len] = 0;
	/* Should contain the same data */
	if (strncmp(data, buf, len) != 0) {
		fail();
		ret = 0;
		goto out;
	}

	/* we should still be able to create mount using mntfd */
	if (move_mount(mntfd, "", AT_FDCWD, "", MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH)) {
		pr_perror("move_mount");
		goto out;
	}

	/* we should be able to umount, if mounted correctly */
	if (umount(dirname)) {
		pr_perror("umount");
		goto out;
	}
	pass();
	ret = 0;
out:
	close(fd);
	close(mntfd);
	return ret;
}
