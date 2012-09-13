#include "zdtmtst.h"

const char *test_doc = "Check, that a TCP connection can be restored\n";
const char *test_author = "Andrey Vagin <avagin@parallels.com";

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

static int port = 8880;

#define BUF_SIZE 1024

int main(int argc, char **argv)
{
	unsigned char buf[BUF_SIZE];
	int fd, fd_s;
	pid_t extpid;
	int res;
	uint32_t crc;
	int pfd[2];

	if (pipe(pfd)) {
		err("pipe() failed");
		return 1;
	}

	extpid = fork();
	if (extpid < 0) {
		err("fork() failed");
		return 1;
	} else if (extpid == 0) {
		test_ext_init(argc, argv);

		close(pfd[1]);
		if (read(pfd[0], &port, sizeof(port)) != sizeof(port)) {
			err("Can't read port\n");
			return 1;
		}

		fd = tcp_init_client("127.0.0.1", port);
		if (fd < 0)
			return 1;

		res = read(fd, buf, BUF_SIZE);
		if (res != BUF_SIZE) {
			err("read less then have to: %d instead of %d", res, BUF_SIZE);
			return 1;
		}
		if (datachk(buf, BUF_SIZE, &crc))
			return 2;

		datagen(buf, BUF_SIZE, &crc);
		if (write(fd, buf, BUF_SIZE) < BUF_SIZE) {
			err("can't write");
			return 1;
		}
		return 0;
	}

	test_init(argc, argv);

	if ((fd_s = tcp_init_server(&port)) < 0) {
		err("initializing server failed");
		return 1;
	}

	close(pfd[0]);
	if (write(pfd[1], &port, sizeof(port)) != sizeof(port)) {
		err("Can't send port");
		return 1;
	}
	close(pfd[1]);

	/*
	 * parent is server of TCP connection
	 */
	fd = tcp_accept_server(fd_s);
	if (fd < 0) {
		err("can't accept client connection %m");
		return 1;
	}

	test_daemon();
	test_waitsig();

	datagen(buf, BUF_SIZE, &crc);
	if (write(fd, buf, BUF_SIZE) < BUF_SIZE) {
		err("can't write");
		return 1;
	}

	res = read(fd, buf, BUF_SIZE);
	if (res != BUF_SIZE) {
		err("read less then have to: %d instead of %d", res, BUF_SIZE);
		return 1;
	}
	if (datachk(buf, BUF_SIZE, &crc))
		return 2;

	pass();
	return 0;
}
