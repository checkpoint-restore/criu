#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include <string.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "zdtmtst.h"
#include "fs.h"

#ifndef LOCK_MAND
#define LOCK_MAND 32
#endif

#ifndef LOCK_READ
#define LOCK_READ 64
#endif

const char *test_doc = "Check that flock locks are restored";
const char *test_author = "Qiang Huang <h.huangqiang@huawei.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

char file0[PATH_MAX];
char file1[PATH_MAX];
char file2[PATH_MAX];
unsigned long inodes[3];
static mnt_info_t *m;
dev_t dev;

static int open_all_files(int *fd_0, int *fd_1, int *fd_2)
{
	struct stat buf;

	snprintf(file0, sizeof(file0), "%s.0", filename);
	snprintf(file1, sizeof(file0), "%s.1", filename);
	snprintf(file2, sizeof(file0), "%s.2", filename);
	*fd_0 = open(file0, O_RDWR | O_CREAT | O_EXCL, 0666);
	if (*fd_0 < 0) {
		pr_perror("Unable to open file %s", file0);
		return -1;
	}

	fstat(*fd_0, &buf);
	inodes[0] = buf.st_ino;

	if (!strcmp(m->fsname, "btrfs"))
		dev = m->s_dev;
	else
		dev = buf.st_dev;

	*fd_1 = open(file1, O_RDWR | O_CREAT | O_EXCL, 0666);
	if (*fd_1 < 0) {
		close(*fd_0);
		unlink(file0);
		pr_perror("Unable to open file %s", file1);
		return -1;
	}

	fstat(*fd_1, &buf);
	inodes[1] = buf.st_ino;

	*fd_2 = open(file2, O_RDWR | O_CREAT | O_EXCL, 0666);
	if (*fd_2 < 0) {
		close(*fd_0);
		close(*fd_1);
		unlink(file0);
		unlink(file1);
		pr_perror("Unable to open file %s", file1);
		return -1;
	}
	fstat(*fd_2, &buf);
	inodes[2] = buf.st_ino;

	return 0;
}

static int check_file_lock(int fd, char *expected_type, char *expected_option, unsigned int expected_dev,
			   unsigned long expected_ino)
{
	char buf[100], fl_flag[16], fl_type[16], fl_option[16];
	int found = 0, num, fl_owner;
	FILE *fp_locks = NULL;
	char path[PATH_MAX];
	unsigned long i_no;
	int maj, min;

	test_msg("check_file_lock: (fsname %s) expecting fd %d type %s option %s dev %u ino %lu\n", m->fsname, fd,
		 expected_type, expected_option, expected_dev, expected_ino);

	snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
	fp_locks = fopen(path, "r");
	if (!fp_locks) {
		pr_perror("Can't open %s", path);
		return -1;
	}

	while (fgets(buf, sizeof(buf), fp_locks)) {
		if (strncmp(buf, "lock:\t", 6) != 0)
			continue;
		test_msg("c: %s", buf);

		memset(fl_flag, 0, sizeof(fl_flag));
		memset(fl_type, 0, sizeof(fl_type));
		memset(fl_option, 0, sizeof(fl_option));

		num = sscanf(buf, "%*s %*d:%s %s %s %d %x:%x:%ld %*d %*s", fl_flag, fl_type, fl_option, &fl_owner, &maj,
			     &min, &i_no);
		if (num < 7) {
			pr_err("Invalid lock info\n");
			break;
		}

		if (!strcmp(m->fsname, "btrfs")) {
			if (MKKDEV(major(maj), minor(min)) != expected_dev)
				continue;
		} else {
			if (makedev(maj, min) != expected_dev)
				continue;
		}

		if (fl_owner != getpid())
			continue;
		if (i_no != expected_ino)
			continue;
		if (strcmp(fl_flag, "FLOCK"))
			continue;
		if (strcmp(fl_type, expected_type))
			continue;
		if (strcmp(fl_option, expected_option))
			continue;
		found++;
	}

	fclose(fp_locks);

	return found == 1 ? 0 : -1;
}

int main(int argc, char **argv)
{
	int fd_0, fd_1, fd_2, ret = 0;

	test_init(argc, argv);

	m = get_cwd_mnt_info();
	if (!m) {
		pr_perror("Can't fetch mountinfo");
		return -1;
	}
	if (!strcmp(m->fsname, "btrfs"))
		m->s_dev = kdev_to_odev(m->s_dev);

	if (open_all_files(&fd_0, &fd_1, &fd_2))
		return -1;

	flock(fd_0, LOCK_SH);
	flock(fd_1, LOCK_EX);

	test_daemon();
	test_waitsig();

	if (check_file_lock(fd_0, "ADVISORY", "READ", dev, inodes[0])) {
		fail("Failed on fd %d", fd_0);
		ret |= 1;
	}
	if (check_file_lock(fd_1, "ADVISORY", "WRITE", dev, inodes[1])) {
		fail("Failed on fd %d", fd_1);
		ret |= 1;
	}
	if (!ret)
		pass();

	close(fd_0);
	close(fd_1);
	close(fd_2);
	unlink(file0);
	unlink(file1);
	unlink(file2);

	return ret;
}
