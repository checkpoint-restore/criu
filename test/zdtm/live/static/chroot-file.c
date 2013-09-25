#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that out-of-root file survives";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);
char *filename;
TEST_OPTION(filename, string, "file name", 1);

#define MSG	"out-file-contents"

static int make_file(char *name)
{
	int fd;

	fd = open(name, O_RDWR | O_CREAT, 0666);
	if (fd < 0)
		return -1;

	if (write(fd, MSG, sizeof(MSG)) != sizeof(MSG))
		return -1;

	return fd;
}

static int check_file(int fd)
{
	char r[sizeof(MSG)];

	lseek(fd, 0, SEEK_SET);
	if (read(fd, r, sizeof(r)) != sizeof(MSG))
		return -1;

	if (memcmp(r, MSG, sizeof(MSG)))
		return -1;

	return 0;
}

#define SUCCESS		0
#define ERR_PIPES	(char)0x7f
/* bitmap of errors */
#define ERR_IN_FILE	1
#define ERR_ROOT	2
#define ERR_DIR		4
#define ERR_CHDIR	8
#define ERR_ROOT2	4

int main(int argc, char **argv)
{
	int pid, pipe_prep[2], pipe_goon[2], pipe_res[2];
	char res;
	int fd, fd2;

	test_init(argc, argv);

	pipe(pipe_prep);
	pipe(pipe_goon);
	pipe(pipe_res);
	pid = test_fork();
	if (pid != 0) {
		close(pipe_prep[1]);
		close(pipe_goon[0]);
		close(pipe_res[1]);

		res = ERR_PIPES;
		read(pipe_prep[0], &res, 1);
		if (res != SUCCESS) {
			if (res == ERR_PIPES)
				err("broken pipes");
			else {
				if (res & ERR_IN_FILE)
					err("inside-root file fail");
				if (res & ERR_ROOT)
					err("chroot fail");
				if (res & ERR_DIR)
					err("mkdir fail");
				if (res & ERR_CHDIR)
					err("chrid fail");
			}
			return 0;
		}

		test_daemon();
		test_waitsig();
		close(pipe_goon[1]);

		res = ERR_PIPES;
		read(pipe_res[0], &res, 1);

		if (res == SUCCESS)
			pass();
		else if (res == ERR_PIPES)
			fail("broken pipes");
		else {
			if (res & ERR_IN_FILE)
				fail("opened file broken");
			if (res & ERR_ROOT)
				fail("open in chroot succeeded");
			if (res & ERR_ROOT2)
				fail("open in chroot might work");
		}

		wait(NULL);
		return 0;
	}

	close(pipe_prep[0]);
	close(pipe_goon[1]);
	close(pipe_res[0]);

	fd = make_file(filename);
	if (fd < 0) {
		res = ERR_IN_FILE;
		goto err;
	}

	if (mkdir(dirname, 0700)) {
		res = ERR_DIR;
		goto err;
	}

	if (chroot(dirname)) {
		res = ERR_ROOT;
		goto err;
	}

	if (chdir("/")) {
		res = ERR_CHDIR;
		goto err;
	}

	res = SUCCESS;
	write(pipe_prep[1], &res, 1);
	close(pipe_prep[1]);
	read(pipe_goon[0], &res, 1);

	res = SUCCESS;

	if (check_file(fd))
		res |= ERR_IN_FILE;

	fd2 = open(filename, O_RDWR);
	if (fd2 >= 0) {
		res |= ERR_ROOT;
		close(fd2);
	} else if (errno != ENOENT)
		res |= ERR_ROOT2;

	write(pipe_res[1], &res, 1);
	exit(0);

err:
	write(pipe_prep[1], &res, 1);
	exit(0);
}
