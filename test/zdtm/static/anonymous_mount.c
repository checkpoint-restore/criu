#include <fcntl.h>
#include <linux/limits.h>
#include <linux/openat2.h>
#include <stdint.h>
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
#define BUFLEN	  1000

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE (1 << 0)
#endif

#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#endif

long sys_openat2(int dirfd, const char *pathname, struct open_how *how, size_t size)
{
	return syscall(__NR_openat2, dirfd, pathname, how, size);
}

long sys_open_tree(int dirfd, char *filename, unsigned int flags)
{
	return syscall(__NR_open_tree, dirfd, filename, flags);
}

long sys_move_mount(int from_dfd, char *from_pathname, int to_dfd,
		    char *to_pathname, unsigned int flags)
{
	return syscall(__NR_move_mount, from_dfd, from_pathname, to_dfd,
		       to_pathname, flags);
}

int main(int argc, char *argv[])
{
	int mntfd, fd, ret = 1;
	uint32_t crc = ~0;
	struct open_how how = {};
	uint8_t buf[BUFLEN];

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
	mntfd = sys_open_tree(AT_FDCWD, dirname, OPEN_TREE_CLONE);
	if (mntfd < 0) {
		pr_perror("open_tree");
		return 1;
	}

	how.flags = O_CREAT | O_RDWR;
	how.mode = 0600;
	how.resolve = 0;
	/* open a file inside the (detached) clone */
	fd = sys_openat2(mntfd, TEST_FILE, &how, sizeof(how));
	if (fd < 0) {
		pr_perror("openat2");
		return 1;
	}

	datagen(buf, BUFLEN, &crc);
	if (write(fd, buf, BUFLEN) != BUFLEN) {
		pr_perror("write");
		return 1;
	}

	/* unmount the original */
	if (umount(dirname)) {
		pr_perror("umount %s", dirname);
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
		pr_perror("openat2");
		close(mntfd);
		return 1;
	}

	if (read(fd, buf, BUFLEN) != BUFLEN) {
		pr_perror("read");
		goto out;
	}

	crc = ~0;
	if (datachk(buf, BUFLEN, &crc)) {
		fail("Data mismatch");
		goto out;
	}

	/* we should still be able to create mount using mntfd */
	if (sys_move_mount(mntfd, "", AT_FDCWD, dirname, MOVE_MOUNT_F_EMPTY_PATH)) {
		if (errno != ENOSYS) {
			pr_perror("move_mount");
			goto out;
		}
	}

	pass();
	ret = 0;
out:
	close(fd);
	umount(dirname);
	close(mntfd);
	return ret;
}
