#include "zdtmtst.h"

#ifdef ZDTM_IPV4V6
#define ZDTM_FAMILY AF_INET
#define ZDTM_SRV_FAMILY AF_INET6
#elif defined(ZDTM_IPV6)
#define ZDTM_FAMILY AF_INET6
#define ZDTM_SRV_FAMILY AF_INET6
#else
#define ZDTM_FAMILY AF_INET
#define ZDTM_SRV_FAMILY AF_INET
#endif

const char *test_doc = "Check, that a TCP listen socket can be dumped and restored\n";
const char *test_author = "Andrey Vagin <avagin@parallels.com";

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <sched.h>
#include <netinet/tcp.h>

static int port = 8880;

#define BUF_SIZE 4096

int read_data(int fd, unsigned char *buf, int size)
{
	int cur = 0;
	int ret;
	while (cur != size) {
		ret = read(fd, buf + cur, size - cur);
		if (ret <= 0)
			return -1;
		cur += ret;
	}

	return 0;
}

int write_data(int fd, const unsigned char *buf, int size)
{
	int cur = 0;
	int ret;

	while (cur != size) {
		ret = write(fd, buf + cur, size - cur);
		if (ret <= 0)
			return -1;
		cur += ret;
	}

	return 0;
}

int main(int argc, char **argv)
{
	unsigned char buf[BUF_SIZE];
	int fd, fd_s, clt;
	uint32_t crc;
	int val;
	socklen_t optlen;


	test_init(argc, argv);

	if ((fd_s = tcp_init_server(ZDTM_SRV_FAMILY, &port)) < 0) {
		pr_err("initializing server failed\n");
		return 1;
	}

	/*
	 *  Create a client socket before C/R to check that it can be connected
	 *  after.
	 */
	clt = socket(ZDTM_FAMILY, SOCK_STREAM, 0);
	if (clt < 0) {
		pr_perror("socket");
		return 1;
	}

	test_daemon();
	test_waitsig();

	clt = tcp_init_client_with_fd(clt, ZDTM_FAMILY, "localhost", port);
	if (clt  < 0)
		return 1;

	/*
	 * parent is server of TCP connection
	 */
	fd = tcp_accept_server(fd_s);
	if (fd < 0) {
		pr_err("can't accept client connection\n");
		return 1;
	}

	val = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val))) {
		pr_perror("setsockopt");
		return 1;
	}

	crc = ~0;
	datagen(buf, BUF_SIZE, &crc);
	if (write_data(fd, buf, BUF_SIZE)) {
		pr_perror("can't write");
		return 1;
	}

	if (read_data(clt, buf, BUF_SIZE)) {
		pr_perror("read less then have to");
		return 1;
	}

	crc = ~0;
	if (datachk(buf, BUF_SIZE, &crc))
		return 2;

	if (write_data(clt, buf, BUF_SIZE)) {
		pr_perror("can't write");
		return 1;
	}

	if (read_data(fd, buf, BUF_SIZE)) {
		pr_perror("read less then have to");
		return 1;
	}

	crc = ~0;
	if (datachk(buf, BUF_SIZE, &crc))
		return 2;
	optlen = sizeof(val);
	if (getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, &optlen)) {
		pr_perror("getsockopt");
		return 1;
	}
	if (val != 1) {
		fail("SO_REUSEADDR are not set for %d\n", fd);
		return 1;
	}

	pass();
	return 0;
}
