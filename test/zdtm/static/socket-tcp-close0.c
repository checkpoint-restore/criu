#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#include "zdtmtst.h"

const char *test_doc = "Check that tcp-close option closes connected tcp socket";
const char *test_author = "Pavel Begunkov <asml.silence@gmail.com>";

static int port = 8880;

static int check_socket_closed(int sk)
{
	int err, buffer = 0;
	struct tcp_info info;
	socklen_t len = sizeof(info);

	err = getsockopt(sk, IPPROTO_TCP, TCP_INFO, (void *)&info, &len);
	if (err != 0) {
		pr_perror("Can't get socket state\n");
		return -1;
	} else if (info.tcpi_state != TCP_CLOSE) {
		pr_err("Invalid socket state (%i)\n", (int)info.tcpi_state);
		return -1;
	}

	err = recv(sk, &buffer, sizeof(buffer), 0);
	if (!err || errno != ENOTCONN) {
		pr_perror("Invalid recv response\n");
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int fd, fd_s, clt;

	test_init(argc, argv);

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
	close(fd_s);

	test_daemon();
	test_waitsig();

	if (check_socket_closed(fd)) {
		fail("Server socket isn't closed\n");
		return 1;
	}
	if (check_socket_closed(clt)) {
		fail("Client socket isn't closed\n");
		return 1;
	}
	pass();
	return 0;
}
