#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include "zdtmtst.h"
#include <unistd.h>

const char *test_doc = "Check C/R of a detached bind file mount, while the original mount is still mounted";
const char *test_author = "Bhavik Sachdev <b.sachdev1904@gmail.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define TEST_FILE "detached-bind-file-mount-file"

int main(int argc, char *argv[])
{
	char mount_path[PATH_MAX], file_mount_path[PATH_MAX], bind_path[PATH_MAX];
	int fd, bind_fd;
	char *data = "detached_file_bind_mount.data";
	size_t len = strlen(data);
	char buf[len + 1];

	test_init(argc, argv);

	if (mkdir(dirname, 0700)) {
		pr_perror("mkdir %s", dirname);
		return 1;
	}

	ssprintf(mount_path, "%s/mnt", dirname);
	if (mkdir(mount_path, 0700)) {
		pr_perror("mkdir %s", mount_path);
		return 1;
	}

	if (mount("none", mount_path, "tmpfs", 0, NULL)) {
		pr_perror("mount %s", mount_path);
		return 1;
	}

	ssprintf(file_mount_path, "%s/mnt/file", dirname);
	fd = open(file_mount_path, O_CREAT | O_RDWR);
	if (fd < 0) {
		pr_perror("open %s", file_mount_path);
		return 1;
	}

	/* create bind file path */
	ssprintf(bind_path, "%s/bind_file", dirname);
	bind_fd = creat(bind_path, O_CREAT);
	if (bind_fd < 0) {
		pr_perror("creat %s", bind_path);
		return 1;
	}
	close(bind_fd);

	if (mount(file_mount_path, bind_path, NULL, MS_BIND, NULL)) {
		pr_perror("bind mount %s", bind_path);
		return 1;
	}

	if (write(fd, data, len) != len) {
		pr_perror("write %s", file_mount_path);
		return 1;
	}

	bind_fd = open(bind_path, O_RDWR);
	if (bind_fd < 0) {
		pr_perror("open %s", bind_path);
		return 1;
	}

	if (umount2(bind_path, MNT_DETACH)) {
		pr_perror("umount2 %s", bind_path);
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (read(bind_fd, buf, len) != len) {
		pr_perror("read %s", bind_path);
		return 1;
	}
	buf[len] = 0;

	/* Should contain the same data */
	if (strncmp(data, buf, len) != 0)
		fail();
	else
		pass();

	close(fd);
	close(bind_fd);
	return 0;
}

