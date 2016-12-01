#include "zdtmtst.h"

#ifdef ZDTM_IPV6
#define ZDTM_FAMILY AF_INET6
#else
#define ZDTM_FAMILY AF_INET
#endif

const char *test_doc = "Check unconnected tcp sockets\n";
const char *test_author = "Andrey Vagin <avagin@openvz.org";

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

static int port = 8880;

union sockaddr_inet {
	struct sockaddr addr;
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
};

int main(int argc, char **argv)
{
	int fd, fd_s, sock, sk;
	union sockaddr_inet addr, src_addr;
	socklen_t aux;

	test_init(argc, argv);

	sk = socket(ZDTM_FAMILY, SOCK_STREAM, 0);
	if (sk < 0) {
		pr_perror("socket");
		return 1;
	}

	if ((fd_s = tcp_init_server(ZDTM_FAMILY, &port)) < 0) {
		pr_err("initializing server failed\n");
		return 1;
	}


	if ((sock = socket(ZDTM_FAMILY, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		pr_perror("can't create socket");
		return -1;
	}

	/* Construct the server address structure */
	memset(&addr, 0, sizeof(addr));
	if (ZDTM_FAMILY == AF_INET) {
		addr.v4.sin_family      = AF_INET;
		inet_pton(AF_INET, "localhost", &addr.v4.sin_addr);
	} else {
		addr.v6.sin6_family      = AF_INET6;
		inet_pton(AF_INET6, "localhost", &addr.v6.sin6_addr);
	}
	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		pr_perror("can't connect to server");
		return -1;
	}
	aux = sizeof(src_addr);
	memset(&src_addr, 0, sizeof(src_addr));
	if (getsockname(sock, &src_addr.addr, &aux)) {
		pr_perror("getsockname");
		return 1;
	}

	test_daemon();
	test_waitsig();

	memset(&addr, 0, sizeof(addr));
	if (getsockname(sock, &addr.addr, &aux)) {
		pr_perror("getsockname");
		return 1;
	}
	if (memcmp(&addr, &src_addr, aux)) {
		pr_err("A source address mismatch");
		return 1;
	}

	/* Construct the server address structure */
	memset(&addr, 0, sizeof(addr));
	if (ZDTM_FAMILY == AF_INET) {
		addr.v4.sin_family      = AF_INET;
		addr.v4.sin_port        = htons(port);
		inet_pton(AF_INET, "localhost", &addr.v4.sin_addr);
	} else {
		addr.v6.sin6_family      = AF_INET6;
		addr.v6.sin6_port        = htons(port);
		inet_pton(AF_INET6, "localhost", &addr.v6.sin6_addr);
	}
	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		pr_perror("can't connect to server");
		return -1;
	}

	/*
	 * parent is server of TCP connection
	 */
	fd = tcp_accept_server(fd_s);
	if (fd < 0) {
		pr_err("can't accept client connection\n");
		return 1;
	}
	close(fd_s);


	pass();
	return 0;
}
