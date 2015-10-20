#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc	= "Open r/w and unlink file, and fork before migration;\n"
			  "check that the child can write to it and the parent\n"
			  "can read from it after migration";
const char *test_author	= "Roman Kagan <rkagan@parallels.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

int main(int argc, char ** argv)
{
	int fd, child_fd, ret;
	pid_t pid;
	uint32_t crc;
	uint8_t buf[1000000];

	test_init(argc, argv);

	fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("can't open %s", filename);
		exit(1);
	}

	child_fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("can't open %s", filename);
		exit(1);
	}

	if (unlink(filename)) {
		pr_perror("can't unlink %s", filename);
		exit(1);
	}

	pid = fork();
	if (pid < 0) {
		pr_perror("can't fork");
		exit(1);
	}

	if (pid == 0) {	/* child writes to the unlinked file and returns */
		close(fd);
		test_waitsig();

		crc = ~0;
		datagen(buf, sizeof(buf), &crc);
		if (write(child_fd, buf, sizeof(buf)) != sizeof(buf))
			_exit(errno);

		close(child_fd);
		_exit(0);
	}

	close(child_fd);

	test_daemon();
	test_waitsig();

	if (kill(pid, SIGTERM)) {
		fail("terminating the child failed: %m\n");
		goto out;
	}

	if (wait(&ret) != pid) {
		fail("wait() returned wrong pid %d: %m\n", pid);
		goto out;
	}

	if (WIFEXITED(ret)) {
		ret = WEXITSTATUS(ret);
		if (ret) {
			fail("child exited with nonzero code %d (%s)\n", ret, strerror(ret));
			goto out;
		}
	}
	if (WIFSIGNALED(ret)) {
		fail("child exited on unexpected signal %d\n", WTERMSIG(ret));
		goto out;
	}

	if (lseek(fd, 0, SEEK_SET) < 0) {
		fail("lseeking to the beginning of file failed: %m\n");
		goto out;
	}

	if (read(fd, buf, sizeof(buf)) != sizeof(buf)) {
		fail("can't read %s: %m\n", filename);
		goto out;
	}

	crc = ~0;
	if (datachk(buf, sizeof(buf), &crc)) {
		fail("CRC mismatch\n");
		goto out;
	}


	if (close(fd)) {
		fail("close failed: %m\n");
		goto out_noclose;
	}

	if (unlink(filename) != -1 || errno != ENOENT) {
		fail("file %s should have been deleted before migration: unlink: %m\n");
		goto out_noclose;
	}

	pass();

out:
	close(fd);
out_noclose:
	return 0;
}
