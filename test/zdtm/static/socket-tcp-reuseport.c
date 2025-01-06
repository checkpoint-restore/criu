#include "zdtmtst.h"

#ifdef ZDTM_IPV6
#define ZDTM_FAMILY AF_INET6
#else
#define ZDTM_FAMILY AF_INET
#endif

const char *test_doc = "Check a case when one port is shared between two listening sockets\n";
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
#include <sys/socket.h>
#include <arpa/inet.h> /* for sockaddr_in and inet_ntoa() */

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
	struct zdtm_tcp_opts opts = { .reuseaddr = false, .reuseport = true, .flags = SOCK_NONBLOCK };
	unsigned char buf[BUF_SIZE];
	int port = 8880, port2;
	int fd, fd_s, fd_s2, clt, i;
	socklen_t optlen;
	int no = 0, val;
	uint32_t crc;

	test_init(argc, argv);

	if ((fd_s = tcp_init_server_with_opts(ZDTM_FAMILY, &port, &opts)) < 0) {
		pr_err("initializing server failed\n");
		return 1;
	}

	port2 = port;
	if ((fd_s2 = tcp_init_server_with_opts(ZDTM_FAMILY, &port2, &opts)) < 0) {
		pr_err("initializing server failed\n");
		return 1;
	}
	if (port != port2)
		return 1;

	if (setsockopt(fd_s, SOL_SOCKET, SO_REUSEPORT, &no, sizeof(int)) == -1) {
		pr_perror("Unable to set SO_REUSEPORT");
		return -1;
	}

	clt = tcp_init_client(ZDTM_FAMILY, "localhost", port);
	if (clt < 0)
		return 1;

	/*
	 * parent is server of TCP connection
	 */
	fd = tcp_accept_server(fd_s);
	if (fd < 0)
		fd = tcp_accept_server(fd_s2);
	if (fd < 0) {
		pr_err("can't accept client connection\n");
		return 1;
	}

	test_daemon();
	test_waitsig();

	optlen = sizeof(val);
	if (getsockopt(fd_s, SOL_SOCKET, SO_REUSEPORT, &val, &optlen)) {
		pr_perror("getsockopt");
		return 1;
	}
	if (val == 1) {
		fail("SO_REUSEPORT is set for %d", fd);
		return 1;
	}
	optlen = sizeof(val);
	if (getsockopt(fd_s2, SOL_SOCKET, SO_REUSEPORT, &val, &optlen)) {
		pr_perror("getsockopt");
		return 1;
	}
	if (val != 1) {
		fail("SO_REUSEPORT is not set for %d", fd);
		return 1;
	}

	for (i = 0;; i++) {
		crc = 0;
		datagen(buf, BUF_SIZE, &crc);
		if (write_data(fd, buf, BUF_SIZE)) {
			pr_perror("can't write");
			return 1;
		}

		memset(buf, 0, BUF_SIZE);
		if (read_data(clt, buf, BUF_SIZE)) {
			pr_perror("read less then have to");
			return 1;
		}
		crc = 0;
		if (datachk(buf, BUF_SIZE, &crc))
			return 2;

		close(clt);
		close(fd);

		if (i == 2)
			break;

		clt = tcp_init_client(ZDTM_FAMILY, "localhost", port);
		if (clt < 0)
			return 1;

		/*
		 * parent is server of TCP connection
		 */
		fd = tcp_accept_server(fd_s2);
		if (fd < 0) {
			fd = tcp_accept_server(fd_s);
			close(fd_s);
		} else {
			close(fd_s2);
		}
		if (fd < 0) {
			pr_err("can't accept client connection %d\n", i);
			return 1;
		}
	}

	pass();
	return 0;
}
