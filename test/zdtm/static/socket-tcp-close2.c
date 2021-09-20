#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <signal.h>

#include "zdtmtst.h"

const char *test_doc = "Check both dump and restore with tcp_close on TCP_CLOSE sockets";
const char *test_author = "Bui Quang Minh <minhquangbui99@gmail.com>";

static int port = 8880;

int main(int argc, char **argv)
{
	int fd_s, fd, client;
	char c;

	test_init(argc, argv);
	signal(SIGPIPE, SIG_IGN);

	fd_s = tcp_init_server(AF_INET, &port);
	if (fd_s < 0) {
		pr_err("Server initializations failed\n");
		return 1;
	}

	client = tcp_init_client(AF_INET, "localhost", port);
	if (client < 0) {
		pr_err("Client initializations failed\n");
		return 1;
	}

	fd = tcp_accept_server(fd_s);
	if (fd < 0) {
		pr_err("Can't accept client\n");
		return 1;
	}
	close(fd_s);

	shutdown(client, SHUT_WR);
	shutdown(fd, SHUT_WR);

	test_daemon();
	test_waitsig();

	if (read(fd, &c, 1) != 0) {
		fail("read server");
		return 1;
	}
	if (read(client, &c, 1) != 0) {
		fail("read client");
		return 1;
	}
	if (write(client, &c, 1) != -1) {
		fail("write client");
		return 1;
	}
	if (write(fd, &c, 1) != -1) {
		fail("write server");
		return 1;
	}

	pass();
	return 0;
}
