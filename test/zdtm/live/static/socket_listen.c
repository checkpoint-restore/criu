#include "zdtmtst.h"

const char *test_doc = "static test for listening socket\n";
const char *test_author = "Stanislav Kinsbursky <skinsbursky@openvz.org>";

/* Description:
 * Create two tcp socket, server send asynchronous request on
 * read data and clietn write data after migration
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <wait.h>

static int port = 8880;

#define BUF_SIZE 1024

static void sig_hand(int signo) {}

int main(int argc, char **argv)
{
	unsigned char buf[BUF_SIZE];
	int fd, fd_s;
	int status;
	pid_t pid;
	int res;
	uint32_t crc;
	struct sigaction sa = {
		.sa_handler	= sig_hand,
		/* don't set SA_RESTART */
	};

	test_init(argc, argv);

	if ((fd_s = tcp_init_server(&port)) < 0) {
		err("initializing server failed");
		return 1;
	}

	test_daemon();
	test_waitsig();

	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGCHLD, &sa, NULL))
		fprintf(stderr, "Can't set SIGTERM handler: %m\n");

	pid = test_fork();
	if (pid < 0) {
		err("fork failed. Return %d %m", pid);
		return 1;
	}

	if (pid == 0) {
		/*
		 * Chiled is client of TCP connection
		 */
		close(fd_s);
		fd = tcp_init_client("127.0.0.1", port);
		if (fd < 0)
			return 1;

		res = read(fd, buf, BUF_SIZE);
		close(fd);
		if (res != BUF_SIZE) {
			err("read less then have to: %d instead of %d", res, BUF_SIZE);
			return -1;
		}
		if (datachk(buf, BUF_SIZE, &crc))
			return -2;
		return 0;
	}

	/*
	 * parent is server of TCP connection
	 */
	fd = tcp_accept_server(fd_s);
	close(fd_s);
	if (fd < 0) {
		err("can't accept client connection %m");
		goto error;
	}

	datagen(buf, BUF_SIZE, &crc);
	if (write(fd, buf, BUF_SIZE) < BUF_SIZE) {
		err("can't write");
		goto error;
	}
	close(fd);


	if (wait(&status) < 0) {
		err("wait failed %m");
		goto error;
	}

	if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
		err("chiled failed. Return %d", WEXITSTATUS(status));
		return 1;
	}

	pass();
	return 0;
error:
	kill(pid, SIGKILL);
	wait(&status);
	return -1;
}
