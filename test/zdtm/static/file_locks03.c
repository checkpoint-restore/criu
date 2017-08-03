#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include <string.h>
#include <sys/wait.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that 'inherited' flocks work";
const char *test_author	= "Pavel Emelyanov <xemul@parallels.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

static int check_file_lock(pid_t pid, pid_t child, int fd, char *expected_type,
			   char *expected_option)
{
	char buf[100], fl_flag[16], fl_type[16], fl_option[16];
	int found = 0, num, fl_owner;
	FILE *fp_locks = NULL;
	char path[PATH_MAX];

	test_msg("check_file_lock: (pid %d child %d) expecting fd %d type %s option %s\n",
		 pid, child, fd, expected_type, expected_option);

	snprintf(path, sizeof(path), "/proc/%d/fdinfo/%d", child, fd);
	fp_locks = fopen(path, "r");
	if (!fp_locks) {
		pr_err("Can't open %s\n", path);
		return -1;
	}

	while (fgets(buf, sizeof(buf), fp_locks)) {
		if (strncmp(buf, "lock:\t", 6) != 0)
			continue;
		test_msg("c: %s", buf);

		memset(fl_flag, 0, sizeof(fl_flag));
		memset(fl_type, 0, sizeof(fl_type));
		memset(fl_option, 0, sizeof(fl_option));

		num = sscanf(buf, "%*s %*d:%s %s %s %d",
			     fl_flag, fl_type, fl_option, &fl_owner);
		if (num < 4) {
			pr_perror("Invalid lock info.");
			break;
		}

		if (fl_owner != pid && fl_owner != child)
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
	int fd, pid, ret = 0;
	task_waiter_t t;

	test_init(argc, argv);
	task_waiter_init(&t);

	fd = open(filename, O_CREAT | O_RDWR, 0600);
	if (fd < 0) {
		pr_perror("No file");
		return -1;
	}

	flock(fd, LOCK_EX);

	pid = fork();
	if (pid == 0) {
		test_waitsig();
		task_waiter_wait4(&t, 1);
		exit(0);
	}

	close(fd);

	test_daemon();
	test_waitsig();

	if (check_file_lock(getpid(), pid, fd, "ADVISORY", "WRITE")) {
		fail("Flock file locks check failed");
		ret |= 1;
	}

	task_waiter_complete(&t, 1);

	if (!ret)
		pass();

	kill(pid, SIGTERM);
	waitpid(pid, NULL, 0);
	unlink(filename);

	return 0;
}
