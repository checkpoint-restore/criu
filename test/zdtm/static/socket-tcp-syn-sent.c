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

const char *test_doc = "Check unconnected tcp sockets\n";
const char *test_author = "Andrey Vagin <avagin@openvz.org";

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
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
	union sockaddr_inet addr;
	char cmd[4096];

	test_init(argc, argv);

	sk = socket(ZDTM_FAMILY, SOCK_STREAM, 0);
	if (sk < 0) {
		pr_perror("socket");
		return 1;
	}

	if ((fd_s = tcp_init_server(ZDTM_SRV_FAMILY, &port)) < 0) {
		pr_err("initializing server failed\n");
		return 1;
	}


	if ((sock = socket(ZDTM_FAMILY, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP)) < 0) {
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

	snprintf(cmd, sizeof(cmd), "iptables -w -t filter --protocol tcp -A INPUT --dport %d -j DROP", port);
	if (system(cmd))
		return -1;

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

	errno = 0;
	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) == 0 || errno != EINPROGRESS) {
		pr_perror("can't connect to server");
		return -1;
	}

	test_daemon();
	test_waitsig();

	snprintf(cmd, sizeof(cmd), "iptables -w -t filter --protocol tcp -D INPUT --dport %d -j DROP", port);
	if (system(cmd))
		return -1;

	/*
	 * parent is server of TCP connection
	 */
	fd = tcp_accept_server(fd_s);
	if (fd < 0) {
		pr_err("can't accept client connection\n");
		return 1;
	}
	close(fd_s);

	fcntl(sock, F_SETFL, 0);

	char c = 5;
	if (write(sock, &c, 1) != 1) {
		fail("Unable to send data");
		return 1;
	}

	c = 0;
	if (read(fd, &c, 1) != 1 || c != 5) {
		fail("Unable to recv data");
		return 1;
	}

	c = 6;
	if (write(fd, &c, 1) != 1) {
		fail("Unable to send data");
		return 1;
	}

	c = 0;
	if (read(sock, &c, 1) != 1 || c != 6) {
		fail("Unable to recv data");
		return 1;
	}


	pass();
	return 0;
}
