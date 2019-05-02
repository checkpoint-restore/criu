#include <sys/file.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "zdtmtst.h"
#include "fs.h"
#include "ofd_file_locks.h"

static int parse_ofd_lock(char *buf, struct flock *lck)
{
	char fl_flag[10], fl_type[15], fl_option[10], fl_end[32];
	long long start;
	int num;

	if (strncmp(buf, "lock:\t", 6) != 0)
		return 1; /* isn't lock, skip record */

	num = sscanf(buf,
		"%*s %*d: %s %s %s %*d %*x:%*x:%*d %lld %s",
		fl_flag, fl_type, fl_option, &start, fl_end);

	if (num < 4) {
		pr_err("Invalid lock info %s\n", buf);
		return -1;
	}
	if (strcmp(fl_flag, "OFDLCK"))
		return 1;

	lck->l_start = start;

	if (strcmp(fl_end, "EOF")) {
		unsigned long end;

		if (sscanf(fl_end, "%lu", &end) <= 0) {
			pr_err("Invalid lock entry\n");
			return -1;
		}
		lck->l_len = end - lck->l_start + 1;
	} else {
		lck->l_len = 0;
	}
	if (strcmp(fl_option, "WRITE") == 0)
		lck->l_type = F_WRLCK;
	else
		lck->l_type = F_RDLCK;

	return 0;
}

static int read_fd_ofd_lock(int pid, int fd, struct flock *lck)
{
	char path[PATH_MAX];
	char buf[100];
	int num;
	FILE *proc_file = NULL;

	sprintf(path, "/proc/%i/fdinfo/%i", pid, fd);
	proc_file = fopen(path, "r");

	if (!proc_file) {
		pr_err("Can't open %s\n", path);
		return -1;
	}

	num = -1;
	while (fgets(buf, sizeof(buf), proc_file)) {
		num = parse_ofd_lock(buf, lck);
		if (num <= 0)
			break;
	}

	if (fclose(proc_file)) {
		pr_err("Can't close %s\n", path);
		return -1;
	}
	return num;
}

int check_lock_exists(const char *filename, struct flock *lck)
{
	int ret = -1;
	int fd;

	fd = open(filename, O_RDWR, 0666);

	if (lck->l_type == F_RDLCK) {
		/* check, that there is no write lock */
		ret = zdtm_fcntl(fd, F_OFD_GETLK, lck);
		if (ret) {
			pr_err("fcntl failed (%i)\n", ret);
			goto out;
		}
		if (lck->l_type != F_UNLCK) {
			pr_err("OFD lock type do not match\n");
			goto out;
		}
	}

	/* check, that lock is set */
	lck->l_type = F_WRLCK;
	ret = zdtm_fcntl(fd, F_OFD_GETLK, lck);
	if (ret) {
		pr_err("fcntl failed (%i)\n", ret);
		goto out;
	}
	if (lck->l_type == F_UNLCK) {
		pr_err("Lock not found\n");
		goto out;
	}

	ret = 0;
out:
	if (close(fd))
		return -1;
	return ret;
}

static int check_file_locks_match(struct flock *orig_lck, struct flock *lck)
{
	return orig_lck->l_start == lck->l_start &&
		orig_lck->l_len == lck->l_len &&
		orig_lck->l_type == lck->l_type;
}

int check_file_lock_restored(int pid, int fd, struct flock *lck)
{
	struct flock lck_restored;

	if (read_fd_ofd_lock(pid, fd, &lck_restored))
		return -1;

	if (!check_file_locks_match(lck, &lck_restored)) {
		pr_err("Can't restore file lock (fd: %i)\n", fd);
		return -1;
	}
	return 0;
}

/*
 * fcntl() wrapper for ofd locks.
 *
 * Kernel requires ia32 processes to use fcntl64() syscall for ofd:
 * COMPAT_SYSCALL_DEFINE3(fcntl, [..])
 * {
 *	switch (cmd) {
 *	case F_GETLK64:
 *	case F_SETLK64:
 *	case F_SETLKW64:
 *	case F_OFD_GETLK:
 *	case F_OFD_SETLK:
 *	case F_OFD_SETLKW:
 *	return -EINVAL;
 * }
 *
 * Glibc does all the needed wraps for fcntl(), but only from v2.28.
 * To make ofd tests run on the older glibc's - provide zdtm wrap.
 *
 * Note: we don't need the wraps in CRIU itself as parasite/restorer
 * run in 64-bit mode as long as possible, including the time to play
 * with ofd (and they are dumped from CRIU).
 */
int zdtm_fcntl(int fd, int cmd, struct flock *f)
{
#if defined(__i386__)
#ifndef __NR_fcntl64
# define __NR_fcntl64 221
#endif
	struct flock64 f64 = {};
	int ret;

	switch (cmd) {
		case F_OFD_SETLK:
		case F_OFD_SETLKW:
			f64.l_type	= f->l_type;
			f64.l_whence	= f->l_whence;
			f64.l_start	= f->l_start;
			f64.l_len	= f->l_len;
			f64.l_pid	= f->l_pid;
			return syscall(__NR_fcntl64, fd, cmd, &f64);
		case F_OFD_GETLK:
			ret = syscall(__NR_fcntl64, fd, cmd, &f64);
			f->l_type	= f64.l_type;
			f->l_whence	= f64.l_whence;
			f->l_start	= f64.l_start;
			f->l_len	= f64.l_len;
			f->l_pid	= f64.l_pid;
			return ret;
		default:
			break;
	}
#endif
	return fcntl(fd, cmd, f);
}
