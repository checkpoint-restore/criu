#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that root didn't change";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);
char *filename;
TEST_OPTION(filename, string, "file name", 1);
static char *filepath;

#define MSG	"chroot-file-contents"

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
#define ERR_OPEN	2
#define ERR_FILE2	4

int main(int argc, char **argv)
{
	int pid, pipe_prep[2], pipe_goon[2], pipe_res[2];
	char res;
	int fd, fd2;

	test_init(argc, argv);

	filepath = malloc(strlen(filename) + 1);
	sprintf(filepath, "/%s", filename);

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
				pr_perror("broken pipes");
			else {
				if (res & ERR_IN_FILE)
					pr_perror("inside-root file fail");
				if (res & ERR_ROOT)
					pr_perror("chroot fail");
				if (res & ERR_DIR)
					pr_perror("mkdir fail");
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
			if (res & ERR_OPEN)
				fail("open in chroot fail");
			if (res & ERR_FILE2)
				fail("wrong file opened");
		}

		wait(NULL);
		return 0;
	}

	close(pipe_prep[0]);
	close(pipe_goon[1]);
	close(pipe_res[0]);

	if (mkdir(dirname, 0700)) {
		res = ERR_DIR;
		goto err_nodir;
	}

	if (chroot(dirname)) {
		res = ERR_ROOT;
		goto err_noroot;
	}

	fd = make_file(filepath);
	if (fd < 0) {
		res = ERR_IN_FILE;
		goto err_nofile2;
	}

	res = SUCCESS;
	write(pipe_prep[1], &res, 1);
	close(pipe_prep[1]);
	read(pipe_goon[0], &res, 1);

	res = SUCCESS;

	if (check_file(fd))
		res |= ERR_IN_FILE;

	fd2 = open(filepath, O_RDWR);
	if (fd2 < 0)
		res |= ERR_OPEN;
	else if (check_file(fd2))
		res |= ERR_FILE2;

	write(pipe_res[1], &res, 1);
	exit(0);

err_nofile2:
err_noroot:
err_nodir:
	write(pipe_prep[1], &res, 1);
	exit(0);
}
