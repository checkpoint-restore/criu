#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc = "Check a read-only nosymfollow ramfs, as systemd mounts for unit credentials";
const char *test_author = "Simon Zhou <jp.zdm2008@gmail.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define RAMFS_MAGIC 0x858458f6
#define TEST_WORD   "credential"

/* Linux 5.10; the values are the kernel's, older headers lack them. */
#define TEST_MS_NOSYMFOLLOW 256
#define TEST_ST_NOSYMFOLLOW 0x2000

#define MNT_FLAGS (ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC)

int main(int argc, char **argv)
{
	char buf[sizeof(TEST_WORD)] = {}, fname[PATH_MAX];
	unsigned long want;
	struct statvfs vfs;
	struct statfs sfs;
	struct stat st;
	int fd, ret = 1;

	test_init(argc, argv);

	/* The shape of /run/credentials/<unit>: ramfs mode=700, a 0400 file. */
	mkdir(dirname, 0755);
	if (mount("none", dirname, "ramfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=700") < 0) {
		fail("Can't mount ramfs");
		return 1;
	}

	snprintf(fname, sizeof(fname), "%s/journal.forward_to_socket", dirname);
	fd = open(fname, O_RDWR | O_CREAT, 0400);
	if (fd < 0 || write(fd, TEST_WORD, sizeof(TEST_WORD)) != sizeof(TEST_WORD)) {
		pr_perror("write");
		goto err;
	}
	close(fd);

	/* Read-only on the mount only: the superblock stays read-write. */
	if (mount(NULL, dirname, NULL,
		  MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | TEST_MS_NOSYMFOLLOW,
		  NULL) < 0) {
		fail("Can't remount ramfs read-only");
		goto err;
	}

	/* A kernel without nosymfollow ignores the flag; then do not demand it. */
	if (statvfs(dirname, &vfs) < 0) {
		pr_perror("statvfs");
		goto err;
	}
	want = MNT_FLAGS | (vfs.f_flag & TEST_ST_NOSYMFOLLOW);
	if ((vfs.f_flag & want) != want) {
		fail("mount flags %#lx before C/R, expected %#lx", vfs.f_flag, want);
		goto err;
	}

	test_daemon();
	test_waitsig();

	if (statfs(dirname, &sfs) < 0 || sfs.f_type != RAMFS_MAGIC) {
		fail("not restored as ramfs");
		goto err;
	}
	if (statvfs(dirname, &vfs) < 0) {
		pr_perror("statvfs");
		goto err;
	}
	if ((vfs.f_flag & want) != want) {
		fail("mount flags %#lx after C/R, expected %#lx", vfs.f_flag, want);
		goto err;
	}
	if (stat(dirname, &st) < 0 || (st.st_mode & 07777) != 0700) {
		fail("ramfs root mode not restored");
		goto err;
	}
	if (stat(fname, &st) < 0 || (st.st_mode & 07777) != 0400) {
		fail("credential mode not restored");
		goto err;
	}

	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		pr_perror("open");
		goto err;
	}
	if (read(fd, buf, sizeof(TEST_WORD)) != sizeof(TEST_WORD) || strcmp(buf, TEST_WORD)) {
		fail("credential content differs");
		close(fd);
		goto err;
	}
	close(fd);

	pass();
	ret = 0;
err:
	umount2(dirname, MNT_DETACH);
	rmdir(dirname);
	return ret;
}
