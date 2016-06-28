#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include <string.h>
#include <limits.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that 'overlapping' flocks work";
const char *test_author	= "Pavel Emelyanov <xemul@parallels.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

static int check_file_locks(pid_t child_pid, int fd, int child_fd)
{
	char		path[PATH_MAX];
	FILE		*fp_locks = NULL;
	char		buf[100], fl_flag[16], fl_type[16], fl_option[16];
	int		found = 0, num, fl_owner;

	sprintf(path, "/proc/%d/fdinfo/%d", child_pid, child_fd);
	fp_locks = fopen(path, "r");
	if (!fp_locks) {
		pr_err("Can't open %s\n", path);
		return -1;
	}

	while (fgets(buf, sizeof(buf), fp_locks)) {
		if (strncmp(buf, "lock:\t", 6) != 0)
			continue;
		test_msg("c: %s", buf);

		num = sscanf(buf,
			"%*s %*d:%s %s %s %d %*02x:%*02x:%*d %*d %*s",
			fl_flag, fl_type, fl_option, &fl_owner);

		if (num < 4) {
			pr_perror("Invalid lock info.");
			break;
		}

		if (fl_owner != child_pid && fl_owner != getpid()) {
			pr_err("Wrong owner\n");
			continue;
		}

		if (!strcmp(fl_flag, "FLOCK") &&
				!strcmp(fl_type, "ADVISORY") &&
				!strcmp(fl_option, "WRITE"))
			found++;

		memset(fl_flag, 0, sizeof(fl_flag));
		memset(fl_type, 0, sizeof(fl_type));
		memset(fl_option, 0, sizeof(fl_option));
	}

	fclose(fp_locks);

	if (flock(fd, LOCK_EX | LOCK_NB) == 0)
		return 0;

	return found == 1;
}

int main(int argc, char **argv)
{
	int fd, child_fd, pid;

	test_init(argc, argv);

	fd = child_fd = open(filename, O_CREAT | O_RDWR, 0600);
	if (fd < 0) {
		pr_perror("No file");
		return -1;
	}

	flock(fd, LOCK_EX);

	pid = fork();
	if (pid == 0) {
		test_waitsig();
		exit(0);
	}

	close(fd);

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		pr_perror("No file 2");
		kill(pid, SIGTERM);
		waitpid(pid, NULL, 0);
		return -1;
	}

	if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
		pr_perror("Bogus locks");
		kill(pid, SIGTERM);
		waitpid(pid, NULL, 0);
		return -1;
	}

	test_daemon();
	test_waitsig();

	if (check_file_locks(pid, fd, child_fd) > 0)
		pass();
	else
		fail("Flock file locks check failed");

	kill(pid, SIGTERM);
	waitpid(pid, NULL, 0);
	close(fd);
	unlink(filename);

	return 0;
}
