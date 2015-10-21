#include "zdtmtst.h"

#ifdef ZDTM_IPV6
#define ZDTM_FAMILY AF_INET6
#else
#define ZDTM_FAMILY AF_INET
#endif

const char *test_doc = "Check, that a TCP socket in the TCP_CLOSE state can be restored\n";
const char *test_author = "Andrey Vagin <avagin@openvz.org";

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <netinet/tcp.h>

static int port = 8880;

int main(int argc, char **argv)
{
	int fd, fd_s, clt;

	test_init(argc, argv);

	if ((fd_s = tcp_init_server(ZDTM_FAMILY, &port)) < 0) {
		pr_err("initializing server failed\n");
		return 1;
	}

	clt = tcp_init_client(ZDTM_FAMILY, "localhost", port);
	if (clt < 0)
		return 1;

	/*
	 * parent is server of TCP connection
	 */
	fd = tcp_accept_server(fd_s);
	if (fd < 0) {
		pr_err("can't accept client connection\n");
		return 1;
	}
	close(fd_s);

	shutdown(fd, SHUT_WR);
	shutdown(clt, SHUT_WR);
	close(fd);

	test_daemon();
	test_waitsig();


	pass();
	return 0;
}
