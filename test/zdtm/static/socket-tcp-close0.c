#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <poll.h>
#include <signal.h>

#include "zdtmtst.h"

const char *test_doc = "Check that tcp-close option closes connected tcp socket";
const char *test_author = "Pavel Begunkov <asml.silence@gmail.com>";

static int port = 8880;

static int check_socket_closed(int sk)
{
	int err, buffer = 0;
	struct {
		__u8 tcpi_state;
	} info;
	socklen_t len = sizeof(info);
	struct pollfd pollfd = {};

	err = getsockopt(sk, IPPROTO_TCP, TCP_INFO, (void *)&info, &len);
	if (err != 0) {
		pr_perror("Can't get socket state");
		return -1;
	} else if (info.tcpi_state != TCP_CLOSE) {
		pr_err("Invalid socket state (%i)\n", (int)info.tcpi_state);
		return -1;
	}

	err = recv(sk, &buffer, sizeof(buffer), MSG_DONTWAIT);
	if (err != 0) {
		pr_perror("Invalid recv response");
		return -1;
	}

	pollfd.fd = sk;
	pollfd.events = POLLHUP;
	if (poll(&pollfd, 1, 0) != 1) {
		pr_perror("poll");
		return 0;
	}

	if (pollfd.revents != POLLHUP) {
		fail("POLLHUP isn't set");
		return 1;
	}

	if (send(sk, "1", 1, MSG_DONTWAIT) != -1) {
		fail("write completed successfully");
		return 1;
	}

	if (errno != EPIPE) {
		fail("wrong errno (expected EPIPE)");
		return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int fd, fd_s, clt;

	test_init(argc, argv);

	/*
	 * check_socket_closed triggers SIGPIPE on attempt of writing into a
	 * closed socket.
	 */
	signal(SIGPIPE, SIG_IGN);

	fd_s = tcp_init_server(AF_INET, &port);
	if (fd_s < 0) {
		pr_err("Server initializations failed\n");
		return 1;
	}
	clt = tcp_init_client(AF_INET, "localhost", port);
	if (clt < 0)
		return 1;

	fd = tcp_accept_server(fd_s);
	if (fd < 0) {
		pr_err("Can't accept client connection\n");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (check_socket_closed(fd)) {
		fail("Server socket isn't closed");
		return 1;
	}
	if (check_socket_closed(clt)) {
		fail("Client socket isn't closed");
		return 1;
	}

	close(clt);
	close(fd);
	clt = tcp_init_client(AF_INET, "localhost", port);
	if (clt < 0)
		return 1;

	fd = tcp_accept_server(fd_s);
	if (fd < 0) {
		pr_err("Can't accept client connection\n");
		return 1;
	}
	pass();
	return 0;
}
