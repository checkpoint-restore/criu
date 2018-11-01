#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <string.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that posix flocks are restored";
const char *test_author	= "Qiang Huang <h.huangqiang@huawei.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

char file0[PATH_MAX];
char file1[PATH_MAX];

static int lock_reg(int fd, int cmd, int type, int whence,
		off_t offset, off_t len)
{
	struct flock lock;

	lock.l_type   = type;     /* F_RDLCK, F_WRLCK, F_UNLCK */
	lock.l_whence = whence;   /* SEEK_SET, SEEK_CUR, SEEK_END */
	lock.l_start  = offset;   /* byte offset, relative to l_whence */
	lock.l_len    = len;      /* #bytes (0 means to EOF) */

	errno = 0;
	return fcntl(fd, cmd, &lock);
}

#define set_read_lock(fd, whence, offset, len) \
	lock_reg(fd, F_SETLK, F_RDLCK, whence, offset, len)
#define set_write_lock(fd, whence, offset, len) \
	lock_reg(fd, F_SETLK, F_WRLCK, whence, offset, len)

static int check_read_lock(int fd, int whence, off_t offset, off_t len)
{
	struct flock lock;
	int ret;

	lock.l_type   = F_RDLCK;  /* F_RDLCK, F_WRLCK, F_UNLCK */
	lock.l_whence = whence;   /* SEEK_SET, SEEK_CUR, SEEK_END */
	lock.l_start  = offset;   /* byte offset, relative to l_whence */
	lock.l_len    = len;      /* #bytes (0 means to EOF) */
	lock.l_pid    = -1;

	errno = 0;
	ret = fcntl(fd, F_GETLK, &lock);
	if (ret == -1) {
		pr_perror("F_GETLK failed.");
		return -1;
	}

	if (lock.l_pid == -1) {
		/* Share lock should succeed. */
		return 0;
	}

	fail("Read lock check failed.");
	return -1;
}

static int check_write_lock(int fd, int whence, off_t offset, off_t len)
{
	struct flock lock;

	int ret;
	pid_t ppid = getppid();

	lock.l_type   = F_WRLCK;  /* F_RDLCK, F_WRLCK, F_UNLCK */
	lock.l_whence = whence;   /* SEEK_SET, SEEK_CUR, SEEK_END */
	lock.l_start  = offset;   /* byte offset, relative to l_whence */
	lock.l_len    = len;      /* #bytes (0 means to EOF) */
	lock.l_pid    = -1;

	errno = 0;
	ret = fcntl(fd, F_GETLK, &lock);
	if (ret == -1) {
		pr_perror("F_GETLK failed.");
		return -1;
	}

	if (lock.l_pid == -1) {
		fail("Write lock check failed.");
		return -1;
	}

	/*
	 * It only succeed when the file lock's owner is exactly
	 * the same as the file lock was dumped.
	 */
	if (lock.l_pid == ppid)
		return 0;

	fail("Write lock check failed.");
	return -1;
}

static int check_file_locks()
{
	int fd_0, fd_1;
	int ret0, ret1;

	fd_0 = open(file0, O_RDWR | O_CREAT, 0644);
	if (fd_0 < 0) {
		pr_perror("Unable to open file %s", file0);
		return -1;
	}
	ret0 = check_read_lock(fd_0, SEEK_SET, 0, 0);

	fd_1 = open(file1, O_RDWR | O_CREAT, 0644);
	if (fd_1 < 0) {
		close(fd_0);
		unlink(file0);
		pr_perror("Unable to open file %s", file1);
		return -1;
	}
	ret1 = check_write_lock(fd_1, SEEK_SET, 0, 0);

	close(fd_0);
	close(fd_1);

	return ret0 | ret1;
}

int main(int argc, char **argv)
{
	int fd_0, fd_1, ret;
	pid_t pid;

	test_init(argc, argv);

	snprintf(file0, sizeof(file0), "%s.0", filename);
	snprintf(file1, sizeof(file0), "%s.1", filename);
	fd_0 = open(file0, O_RDWR | O_CREAT | O_EXCL, 0666);
	if (fd_0 < 0) {
		pr_perror("Unable to open file %s", file0);
		return -1;
	}

	fd_1 = open(file1, O_RDWR | O_CREAT | O_EXCL, 0666);
	if (fd_1 < 0) {
		close(fd_0);
		unlink(file0);
		pr_perror("Unable to open file %s", file1);
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		pr_perror("Can't fork");
		return -1;
	}

	if (pid == 0) {	/* child will check father's file locks */
		test_waitsig();

		if (check_file_locks()) {
			fail("Posix file lock check failed");
			exit(1);
		}

		pass();
		exit(0);
	}

	ret = set_read_lock(fd_0, SEEK_SET, 0, 0);
	if (ret == -1) {
		pr_perror("Failed to set read lock");
		kill(pid, SIGTERM);
		return -1;
	}

	ret = set_write_lock(fd_1, SEEK_SET, 0, 0);
	if (ret == -1) {
		pr_perror("Failed to set write lock");
		kill(pid, SIGTERM);
		return -1;
	}

	test_daemon();
	test_waitsig();

	kill(pid, SIGTERM);
	waitpid(pid, NULL, 0);
	close(fd_0);
	close(fd_1);
	unlink(file0);
	unlink(file1);

	return 0;
}
