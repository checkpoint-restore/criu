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

const char *test_doc	= "Check that flock locks are restored";
const char *test_author	= "Qiang Huang <h.huangqiang@huawei.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

char file0[PATH_MAX];
char file1[PATH_MAX];
char file2[PATH_MAX];
unsigned int inodes[3];
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

static int check_file_locks()
{
	FILE		*fp_locks = NULL;
	char		buf[100];

	long long	fl_id = 0;
	char		fl_flag[10], fl_type[15], fl_option[10];
	pid_t		fl_owner;
	int		maj, min;
	unsigned long	i_no;
	long long	start;
	char		end[32];

	int		num;
	int		count = 3;

	fp_locks = fopen("/proc/locks", "r");
	if (!fp_locks)
		return -1;

	test_msg("C: %d/%d/%d\n", inodes[0], inodes[1], inodes[2]);

	while (fgets(buf, sizeof(buf), fp_locks)) {
		test_msg("c: %s", buf);

		if (strstr(buf, "->"))
			continue;

		num = sscanf(buf,
			"%lld:%s %s %s %d %x:%x:%ld %lld %s",
			&fl_id, fl_flag, fl_type, fl_option,
			&fl_owner, &maj, &min, &i_no, &start, end);

		if (num < 10) {
			pr_perror("Invalid lock info.");
			break;
		}

		if (i_no != inodes[0] && i_no != inodes[1] && i_no != inodes[2])
			continue;

		if (!strcmp(m->fsname, "btrfs")) {
			if (MKKDEV(major(maj), minor(min)) != dev)
				continue;
		} else {
			if (makedev(maj, min) != dev)
				continue;
		}

		if (!strcmp(fl_flag, "FLOCK") && !strcmp(fl_type, "ADVISORY")) {
			if (!strcmp(fl_option, "READ"))
				count--;
			else if (!strcmp(fl_option, "WRITE"))
				count--;
		}

		if (!strcmp(fl_flag, "FLOCK") &&
		    !strcmp(fl_type, "MSNFS") &&
		    !strcmp(fl_option, "READ"))
			count--;

		memset(fl_flag, 0, sizeof(fl_flag));
		memset(fl_type, 0, sizeof(fl_type));
		memset(fl_option, 0, sizeof(fl_option));
	}

	fclose(fp_locks);

	/*
	 * If we find all three matched file locks, count would be 0,
	 * return 0 for success.
	 */
	return count;
}

int main(int argc, char **argv)
{
	int fd_0, fd_1, fd_2;

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
	flock(fd_2, LOCK_MAND | LOCK_READ);

	test_daemon();
	test_waitsig();

	if (check_file_locks())
		fail("Flock file locks check failed");
	else
		pass();

	close(fd_0);
	close(fd_1);
	close(fd_2);
	unlink(file0);
	unlink(file1);
	unlink(file2);

	return 0;
}
