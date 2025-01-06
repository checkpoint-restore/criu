#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <linux/types.h>

#include "zdtmtst.h"

const char *test_doc = "Check that tcp-close option doesn't close listening tcp socket";
const char *test_author = "Pavel Begunkov <asml.silence@gmail.com>";

static int port = 8880;

static int check_socket_state(int sk, int state)
{
	int err;
	struct {
		__u8 tcpi_state;
	} info;
	socklen_t len = sizeof(info);

	err = getsockopt(sk, IPPROTO_TCP, TCP_INFO, (void *)&info, &len);
	if (err != 0) {
		pr_perror("Can't get socket state");
		return -1;
	}
	return info.tcpi_state == state ? 0 : -1;
}

int main(int argc, char **argv)
{
	int fd_s;

	test_init(argc, argv);

	fd_s = tcp_init_server(AF_INET, &port);
	if (fd_s < 0) {
		pr_err("Server initializations failed\n");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (check_socket_state(fd_s, TCP_LISTEN)) {
		fail("Listen socket state is changed");
		close(fd_s);
		return 1;
	}
	close(fd_s);
	pass();
	return 0;
}
