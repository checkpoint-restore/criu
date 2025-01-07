#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc = "Fill/read file continuously to check"
		       "it's migrated at the right moment";
const char *test_author = "Pavel Emelianov <xemul@parallels.com>";

#define MAX_SCALE 128
#define FILE_SIZE (16 * 1024)

enum kids_exit_codes {
	SUCCESS = 0,
	FILE_CORRUPTED,
	MMAP_FAILED,
	OPEN_FAILED,
	WRITE_FAILED,
	READ_FAILED,
	FSYNC_FAILED,
	SEEK_FAILED,

	MAX_EXIT_CODE_VAL
};

static char *kids_fail_reasons[] = { "Success",
				     /* 1 */ "File corrupted",
				     /* 2 */ "Map failed",
				     /* 3 */ "Open (create) failed",
				     /* 4 */ "Write failed",
				     /* 5 */ "Read failed",
				     /* 6 */ "Fsync failed",
				     /* 7 */ "Lseek failed" };

int scale = 13;
TEST_OPTION(scale, int, "How many children should perform testing", 0);

char *filename;
TEST_OPTION(filename, string, "file name", 1);

static int pids[MAX_SCALE];
static volatile int stop = 0;

static void killall(void)
{
	int i;

	for (i = 0; i < MAX_SCALE; i++)
		kill(pids[i], SIGUSR2);
}

static void do_stop(int sig)
{
	stop = 1;
}

static char *buf;

static void prepare_buf(void)
{
	int i;

	for (i = 0; i < FILE_SIZE; i++)
		buf[i] = rand();
}

static int fill_file(int fd)
{
	int rv, wr;

	if (lseek(fd, 0, SEEK_SET) == -1)
		return -2;

	wr = 0;
	while (1) {
		rv = write(fd, buf + wr, FILE_SIZE - wr);
		if (rv <= 0)
			return -1;
		wr += rv;
		if (wr == FILE_SIZE)
			break;
	}
	return 0;
}

static int check_file(int fd)
{
	char rbuf[1024];
	int rv, rd;

	if (lseek(fd, 0, SEEK_SET) == -1)
		return -2;

	rd = 0;
	while (1) {
		rv = read(fd, rbuf, 1024);
		if (rv <= 0)
			return -1;
		if (memcmp(buf + rd, rbuf, rv))
			return 1;
		rd += rv;
		if (rd == FILE_SIZE)
			break;
	}
	return 0;
}

static void chew_some_file(int num)
{
	int fd, rv;
	char chew_file[PATH_MAX];

	buf = mmap(NULL, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	rv = MMAP_FAILED;
	if (buf == MAP_FAILED)
		goto out_exit;

	sprintf(chew_file, "chew_%s.%d", filename, num);
	fd = open(chew_file, O_CREAT | O_EXCL | O_RDWR, 0666);
	rv = OPEN_FAILED;
	if (fd == -1)
		goto out_unmap;

	while (!stop) {
		prepare_buf();
		switch (fill_file(fd)) {
		case -1:
			rv = WRITE_FAILED;
			goto out_exit;
		case -2:
			rv = SEEK_FAILED;
			goto out_exit;
		}
		if (fsync(fd) == -1) {
			rv = FSYNC_FAILED;
			goto out_exit;
		}
		if (fsync(fd) == -1) {
			rv = FSYNC_FAILED;
			goto out_exit;
		}
		switch (check_file(fd)) {
		case -1:
			rv = READ_FAILED;
			goto out_exit;
		case -2:
			rv = SEEK_FAILED;
			goto out_exit;
		case 1: {
			int fd1;
			char str[PATH_MAX];

			rv = FILE_CORRUPTED;
			// create standard file
			sprintf(str, "standard_%s.%d", filename, num);
			fd1 = open(str, O_WRONLY | O_CREAT | O_TRUNC, 0666);
			if (write(fd1, buf, FILE_SIZE) != FILE_SIZE)
				pr_perror("can't write %s", str);
			close(fd1);
			goto out_exit;
		}
		}
	}
	rv = SUCCESS;
	close(fd);
	unlink(chew_file);
out_unmap:
	munmap(buf, FILE_SIZE);
out_exit:
	exit(rv);
}

int main(int argc, char **argv)
{
	int rv, i;
	int counter = 0;

	test_init(argc, argv);

	if (scale > MAX_SCALE) {
		pr_err("Too many children specified\n");
		exit(-1);
	}

	if (signal(SIGUSR2, do_stop) == SIG_ERR) {
		pr_perror("Can't setup signal handler");
		exit(-1);
	}

	for (i = 0; i < scale; i++) {
		rv = test_fork();
		if (rv == -1) {
			pr_perror("Can't fork");
			killall();
			exit(-1);
		}
		if (rv == 0)
			chew_some_file(i);
		pids[i] = rv;
	}

	test_daemon();
	test_waitsig();

	killall();
	for (i = 0; i < scale; i++) {
		if (waitpid(pids[i], &rv, 0) == -1) {
			fail("Can't wipe up the kid");
			counter++;
			continue;
		}
		if (!WIFEXITED(rv)) {
			fail("Kid was killed");
			counter++;
		} else {
			rv = WEXITSTATUS(rv);
			if (rv < MAX_EXIT_CODE_VAL && rv > SUCCESS) {
				fail("Kid failed: %s (%d)", kids_fail_reasons[rv], rv);
				counter++;
			} else if (rv != SUCCESS) {
				fail("Unknown exitcode from kid: %d", rv);
				counter++;
			}
		}
	}

	if (counter == 0)
		pass();
	return 0;
}
