#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <poll.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc = "Check that O_RDONLY|O_NONBLOCK fifos keep their POLLHUP state after restore";
const char *test_author = "Emir Buljubasic <emir.buljubasic@bicomsystems.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

#define FIFO_SIZE (1 << 20)

static int hup(int fd, int timeout)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	int ret;

	ret = poll(&pfd, 1, timeout);
	if (ret < 0) {
		pr_perror("poll() failed");
		return -1;
	}

	return (ret > 0 && (pfd.revents & (POLLHUP | POLLERR)));
}

static int open_fifo_ro(const char *path)
{
	int fd;

	if (mknod(path, S_IFIFO | 0600, 0)) {
		pr_perror("can't make fifo \"%s\"", path);
		return -1;
	}

	fd = open(path, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		pr_perror("can't open %s", path);
		return -1;
	}

	return fd;
}

int main(int argc, char **argv)
{
	char hup_name[PATH_MAX];
	int fd, fd2, fd_hup, fdw;
	char buf[1];

	test_init(argc, argv);

	snprintf(hup_name, sizeof(hup_name), "%s.hup", filename);

	/*
	 * The read end is opened before any writer shows up -- this mirrors
	 * how openrc-init holds its control fifo. The kernel suppresses
	 * POLLHUP for such a reader, so poll() blocks instead of spinning.
	 */
	fd = open_fifo_ro(filename);
	if (fd < 0)
		return 1;

	if (fcntl(fd, F_SETPIPE_SZ, FIFO_SIZE) < 0) {
		pr_perror("can't set pipe size on %s", filename);
		return 1;
	}

	/*
	 * A second end waiting on the same fifo. Restoring one of them must
	 * not hang up the other, as w_counter is per inode.
	 */
	fd2 = open(filename, O_RDONLY | O_NONBLOCK);
	if (fd2 < 0) {
		pr_perror("can't open %s", filename);
		return 1;
	}

	/*
	 * The second fifo has seen a writer come and go, so its read end is
	 * a closed pipe and has to keep reporting POLLHUP.
	 */
	fd_hup = open_fifo_ro(hup_name);
	if (fd_hup < 0)
		return 1;

	fdw = open(hup_name, O_WRONLY);
	if (fdw < 0) {
		pr_perror("can't open %s for writing", hup_name);
		return 1;
	}
	close(fdw);

	/* Sanity checks before C/R. */
	switch (hup(fd, 0)) {
	case -1:
		pr_err("poll() failed before C/R\n");
		return 1;
	case 1:
		pr_err("fifo reports POLLHUP before C/R\n");
		return 1;
	}

	switch (hup(fd2, 0)) {
	case -1:
		pr_err("poll() failed before C/R\n");
		return 1;
	case 1:
		pr_err("second fifo end reports POLLHUP before C/R\n");
		return 1;
	}

	switch (hup(fd_hup, 0)) {
	case -1:
		pr_err("poll() failed before C/R\n");
		return 1;
	case 0:
		pr_err("closed fifo doesn't report POLLHUP before C/R\n");
		return 1;
	}

	test_daemon();
	test_waitsig();

	/*
	 * After restore poll() must still not report POLLHUP. If it does,
	 * CRIU reopened the reader while a (fake) writer was present, and the
	 * application would busy-loop at 100% CPU.
	 */
	switch (hup(fd, 100)) {
	case -1:
		fail("poll() failed after restore");
		return 1;
	case 1:
		fail("fifo reports POLLHUP after restore -- would busy-loop");
		return 1;
	}

	switch (hup(fd2, 100)) {
	case -1:
		fail("poll() failed after restore");
		return 1;
	case 1:
		fail("second fifo end reports POLLHUP after restore");
		return 1;
	}

	/*
	 * The pipe size must survive the restore even though CRIU reopens
	 * the reader against a writer-less (freshly created) pipe object.
	 */
	if (fcntl(fd, F_GETPIPE_SZ) != FIFO_SIZE) {
		fail("fifo lost its pipe size after restore");
		return 1;
	}

	/* A fifo whose writer is gone has to stay hung up. */
	switch (hup(fd_hup, 100)) {
	case -1:
		fail("poll() failed after restore");
		return 1;
	case 0:
		fail("closed fifo doesn't report POLLHUP after restore");
		return 1;
	}

	if (read(fd_hup, buf, sizeof(buf)) != 0) {
		fail("closed fifo hasn't been restored as closed");
		return 1;
	}

	if (close(fd) < 0 || close(fd2) < 0 || close(fd_hup) < 0) {
		fail("can't close fifos");
		return 1;
	}

	if (unlink(filename) < 0 || unlink(hup_name) < 0) {
		fail("can't unlink fifos");
		return 1;
	}

	pass();
	return 0;
}
