#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc = "dynamic FIFO test";

#define PROCS_DEF 2 /* 0 - parent, 1 - child */
#define BUF_SIZE  256
unsigned int num_procs = PROCS_DEF;
char *filename;
TEST_OPTION(filename, string, "file name", 1);

int main(int argc, char **argv)
{
	int ret = 0;
	int readfd, writefd;
	mode_t mode = S_IFIFO | 0600;
	char path[PROCS_DEF][BUF_SIZE];
	pid_t pid;
	int i;
	uint8_t buf[0x100000];
	int chret;
	char *file_path;

	test_init(argc, argv);

	for (i = 0; i < PROCS_DEF; i++) {
		file_path = path[i];
		if (snprintf(file_path, BUF_SIZE, "%s-%02d", filename, i) >= BUF_SIZE) {
			pr_perror("filename %s is too long", filename);
			exit(1);
		}
		if (mkfifo(file_path, mode)) {
			pr_perror("can't make fifo \"%s\"", file_path);
			exit(1);
		}
	}

	pid = test_fork();
	if (pid < 0) {
		pr_perror("Can't fork");
		kill(0, SIGKILL);
		exit(1);
	}
	if (pid == 0) {
		file_path = path[0];
		readfd = open(file_path, O_RDONLY);
		if (readfd < 0) {
			pr_perror("open(%s, O_RDONLY) Failed", file_path);
			ret = errno;
			return ret;
		}
		file_path = path[1];
		writefd = open(file_path, O_WRONLY);
		if (writefd < 0) {
			pr_perror("open(%s, O_WRONLY) Failed", file_path);
			ret = errno;
			return ret;
		}

		if (pipe_in2out(readfd, writefd, buf, sizeof(buf)) < 0)
			/* pass errno as exit code to the parent */
			if (test_go() /* signal NOT delivered */ || (errno != EINTR && errno != EPIPE))
				ret = errno;
		close(readfd);
		close(writefd);
		exit(ret);
	}
	file_path = path[0];
	writefd = open(file_path, O_WRONLY);
	if (writefd < 0) {
		pr_perror("open(%s, O_WRONLY) Failed", file_path);
		kill(pid, SIGKILL);
		return 1;
	}

	file_path = path[1];
	readfd = open(file_path, O_RDONLY);
	if (readfd < 0) {
		pr_perror("open(%s, O_RDONLY) Failed", file_path);
		kill(pid, SIGKILL);
		return 1;
	}
	test_daemon();

	while (test_go()) {
		int len, rlen = 0, wlen;
		uint8_t rbuf[sizeof(buf)], *p;

		datagen(buf, sizeof(buf), NULL);
		wlen = write(writefd, buf, sizeof(buf));
		if (wlen < 0) {
			if (errno == EINTR)
				continue;
			else {
				fail("write failed");
				ret = 1;
				break;
			}
		}

		for (p = rbuf, len = wlen; len > 0; p += rlen, len -= rlen) {
			rlen = read(readfd, p, len);
			if (rlen <= 0)
				break;
		}

		if (rlen < 0 && errno == EINTR)
			continue;

		if (len > 0) {
			fail("read failed");
			ret = 1;
			break;
		}

		if (memcmp(buf, rbuf, wlen)) {
			fail("data mismatch");
			ret = 1;
			break;
		}
	}

	close(writefd);
	test_waitsig();

	wait(&chret);
	chret = WEXITSTATUS(chret);
	if (chret) {
		fail("child exited with non-zero code %d (%s)", chret, strerror(chret));
		return 1;
	}
	if (!ret)
		pass();
	close(readfd);
	for (i = 0; i < PROCS_DEF; i++)
		unlink(path[i]);
	return 0;
}
