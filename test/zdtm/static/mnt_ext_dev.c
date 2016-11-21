#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc	= "Check mounts of external devices";
const char *test_author	= "Andrei Vagin <avagin@virtuozzo.com";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	char *loop, fd, dfd, fd2;
	test_init(argc, argv);
	struct stat st, stp, st2;
	char dname[PATH_MAX], dname2[PATH_MAX];

	snprintf(dname, sizeof(dname), "%s/test_dir", dirname);
	snprintf(dname2, sizeof(dname2), "%s/test_dir2", dirname);

	mkdir(dirname, 0777);
	loop = getenv("ZDTM_MNT_EXT_DEV");
	if (loop == NULL) {
		pr_perror("ZDTM_MNT_EXT_DEV is not set");
		return 1;
	}

	if (mount(loop, dirname, "ext4", 0, NULL) == -1) {
		pr_perror("mount");
		return -1;
	}

	dfd = open(dirname, O_RDONLY);
	if (dfd < 0) {
		pr_perror("open");
		return -1;
	}

	fd = openat(dfd, "test_file", O_RDWR | O_CREAT, 0666);
	if (fd < 0) {
		pr_perror("open");
		return -1;
	}

	if (fstat(fd, &st) < 0) {
		pr_perror("stat");
		return 1;
	}

	mkdir(dname, 0777);
	mkdir(dname2, 0777);

	if (mount(dname, dname2, NULL, MS_BIND, NULL)) {
		pr_perror("mount");
		return 1;
	}
	fd2 = openat(dfd, "test_dir2/test_file2", O_RDWR | O_CREAT, 0666);
	if (fd2 < 0) {
		pr_perror("open");
		return -1;
	}

	if (fstat(fd2, &st2) < 0) {
		pr_perror("stat");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (fstat(fd, &stp) < 0) {
		pr_perror("stat");
		return 1;
	}

	if (st.st_ino != stp.st_ino) {
		fail("file1");
		return 1;
	}

	if (fstat(fd2, &stp) < 0) {
		pr_perror("stat");
		return 1;
	}

	if (st2.st_ino != stp.st_ino) {
		fail("file2");
		return 1;
	}

	if (umount2(dname2, MNT_DETACH)) {
		pr_perror("umount");
		return 1;
	}

	pass();

	return 0;
}
