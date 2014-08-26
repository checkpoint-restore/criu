#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include <string.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that 'shared' flocks work";
const char *test_author	= "Pavel Emelyanov <xemul@parallels.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

static int check_file_locks()
{
	FILE		*fp_locks = NULL;
	char		buf[100], fl_flag[16], fl_type[16], fl_option[16];
	pid_t		pid = getpid();
	int		found = 0, num, fl_owner;

	fp_locks = fopen("/proc/locks", "r");
	if (!fp_locks)
		return -1;

	while (fgets(buf, sizeof(buf), fp_locks)) {
		if (strstr(buf, "->"))
			continue;

		num = sscanf(buf,
			"%*d:%s %s %s %d %*02x:%*02x:%*d %*d %*s",
			fl_flag, fl_type, fl_option, &fl_owner);

		if (num < 4) {
			err("Invalid lock info.\n");
			break;
		}

		if (fl_owner != pid)
			continue;

		if (!strcmp(fl_flag, "FLOCK") &&
				!strcmp(fl_type, "ADVISORY") &&
				!strcmp(fl_option, "WRITE"))
			found++;

		memset(fl_flag, 0, sizeof(fl_flag));
		memset(fl_type, 0, sizeof(fl_type));
		memset(fl_option, 0, sizeof(fl_option));
	}

	fclose(fp_locks);

	return found == 1;
}

int main(int argc, char **argv)
{
	int fd, pf[2], pid;

	test_init(argc, argv);

	pipe(pf);

	fd = open(filename, O_CREAT | O_RDWR, 0600);
	if (fd < 0) {
		err("No file");
		return -1;
	}

	flock(fd, LOCK_EX);

	pid = fork();
	if (pid == 0) {
		close(pf[1]);
		read(pf[0], &pid, sizeof(pid));
		exit(0);
	}

	close(pf[0]);

	test_daemon();
	test_waitsig();

	if (check_file_locks())
		pass();
	else
		fail("Flock file locks check failed");

	close(pf[1]);
	waitpid(pid, NULL, 0);
	close(fd);
	unlink(filename);

	return 0;
}
