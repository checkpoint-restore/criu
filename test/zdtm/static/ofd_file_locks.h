#ifndef ZDTM_OFD_FILE_LOCKS_H_
#define ZDTM_OFD_FILE_LOCKS_H_

#include <sys/file.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "zdtmtst.h"
#include "fs.h"

#ifndef F_OFD_GETLK
#define F_OFD_GETLK	36
#define F_OFD_SETLK	37
#define F_OFD_SETLKW	38
#endif

/*
 * Header library for parsing of OFD locks
 * from procfs and checking them after restoring.
 */

static int parse_ofd_lock(char *buf, struct flock64 *lck)
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

static int read_fd_ofd_lock(int pid, int fd, struct flock64 *lck)
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

static int check_lock_exists(const char *filename, struct flock64 *lck)
{
	int ret = -1;
	int fd;

	fd = open(filename, O_RDWR, 0666);

	if (lck->l_type == F_RDLCK) {
		/* check, that there is no write lock */
		ret = fcntl(fd, F_OFD_GETLK, lck);
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
	ret = fcntl(fd, F_OFD_GETLK, lck);
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

static int check_file_locks_match(struct flock64 *orig_lck, struct flock64 *lck)
{
	return orig_lck->l_start == lck->l_start &&
		orig_lck->l_len == lck->l_len &&
		orig_lck->l_type == lck->l_type;
}

static int check_file_lock_restored(int pid, int fd, struct flock64 *lck)
{
	struct flock64 lck_restored;

	if (read_fd_ofd_lock(pid, fd, &lck_restored))
		return -1;

	if (!check_file_locks_match(lck, &lck_restored)) {
		pr_err("Can't restore file lock (fd: %i)\n", fd);
		return -1;
	}
	return 0;
}

#endif /* ZDTM_OFD_FILE_LOCKS_H_ */
