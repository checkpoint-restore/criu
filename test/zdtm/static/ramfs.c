#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc = "Check that ramfs content is preserved";
const char *test_author = "Simon Zhou <jp.zdm2008@gmail.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define RAMFS_MAGIC 0x858458f6
#define TEST_WORD   "ramfs-content"

static int check_file(const char *path, mode_t mode)
{
	char buf[sizeof(TEST_WORD)] = {};
	struct stat st;
	int fd;

	if (stat(path, &st) < 0) {
		pr_perror("stat(%s)", path);
		return -1;
	}
	if ((st.st_mode & 07777) != mode) {
		fail("%s has mode %o, expected %o", path, st.st_mode & 07777, mode);
		return -1;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("open(%s)", path);
		return -1;
	}
	if (read(fd, buf, sizeof(TEST_WORD)) != sizeof(TEST_WORD) || strcmp(buf, TEST_WORD)) {
		fail("%s content differs", path);
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

int main(int argc, char **argv)
{
	char path[PATH_MAX], sub[PATH_MAX], link[PATH_MAX], target[PATH_MAX];
	struct statfs sfs;
	struct stat st;
	int fd, ret = 1;
	ssize_t len;

	test_init(argc, argv);

	mkdir(dirname, 0755);
	if (mount("none", dirname, "ramfs", 0, "mode=750") < 0) {
		fail("Can't mount ramfs");
		return 1;
	}

	snprintf(sub, sizeof(sub), "%s/sub", dirname);
	snprintf(path, sizeof(path), "%s/sub/file", dirname);
	snprintf(link, sizeof(link), "%s/link", dirname);

	if (mkdir(sub, 0711) < 0) {
		pr_perror("mkdir");
		goto err;
	}
	fd = open(path, O_RDWR | O_CREAT, 0640);
	if (fd < 0 || write(fd, TEST_WORD, sizeof(TEST_WORD)) != sizeof(TEST_WORD)) {
		pr_perror("write");
		goto err;
	}
	close(fd);
	if (chmod(path, 0640) < 0 || symlink("sub/file", link) < 0) {
		pr_perror("chmod/symlink");
		goto err;
	}

	test_daemon();
	test_waitsig();

	if (statfs(dirname, &sfs) < 0) {
		pr_perror("statfs");
		goto err;
	}
	if (sfs.f_type != RAMFS_MAGIC) {
		fail("restored as fs type %#lx, not ramfs", (unsigned long)sfs.f_type);
		goto err;
	}
	if (stat(dirname, &st) < 0 || (st.st_mode & 07777) != 0750) {
		fail("ramfs root mode not restored");
		goto err;
	}
	if (stat(sub, &st) < 0 || (st.st_mode & 07777) != 0711) {
		fail("directory mode not restored");
		goto err;
	}
	if (check_file(path, 0640))
		goto err;
	len = readlink(link, target, sizeof(target) - 1);
	if (len < 0) {
		fail("symlink lost");
		goto err;
	}
	target[len] = '\0';
	if (strcmp(target, "sub/file")) {
		fail("symlink points to %s", target);
		goto err;
	}

	pass();
	ret = 0;
err:
	umount2(dirname, MNT_DETACH);
	rmdir(dirname);
	return ret;
}
