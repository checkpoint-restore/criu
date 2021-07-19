#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h> /* for sockaddr_in and inet_ntoa() */

#include "zdtmtst.h"

union sockaddr_inet {
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
};

int tcp_init_server(int family, int *port)
{
	struct zdtm_tcp_opts opts = {
		.reuseaddr = true,
		.reuseport = false,
	};

	return tcp_init_server_with_opts(family, port, &opts);
}

int tcp_init_server_with_opts(int family, int *port, struct zdtm_tcp_opts *opts)
{
	union sockaddr_inet addr;
	int sock;
	int yes = 1, ret;

	memset(&addr, 0, sizeof(addr));
	if (family == AF_INET) {
		addr.v4.sin_family = family;
		inet_pton(family, "0.0.0.0", &(addr.v4.sin_addr));
	} else if (family == AF_INET6) {
		addr.v6.sin6_family = family;
		inet_pton(family, "::0", &(addr.v6.sin6_addr));
	} else
		return -1;

	sock = socket(family, SOCK_STREAM | opts->flags, IPPROTO_TCP);
	if (sock == -1) {
		pr_perror("socket() failed");
		return -1;
	}

	if (opts->reuseport && setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(int)) == -1) {
		pr_perror("setsockopt(SO_REUSEPORT) failed");
		return -1;
	}

	if (opts->reuseaddr && setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		pr_perror("setsockopt(SO_REUSEATTR) failed");
		return -1;
	}

	while (1) {
		if (family == AF_INET)
			addr.v4.sin_port = htons(*port);
		else if (family == AF_INET6)
			addr.v6.sin6_port = htons(*port);

		ret = bind(sock, (struct sockaddr *)&addr, sizeof(addr));

		/* criu doesn't restore sock opts, so we need this hack */
		if (ret == -1 && errno == EADDRINUSE) {
			test_msg("The port %d is already in use.\n", *port);
			(*port)++;
			continue;
		}
		break;
	}

	if (ret == -1) {
		pr_perror("bind() failed");
		return -1;
	}

	if (listen(sock, 1) == -1) {
		pr_perror("listen() failed");
		return -1;
	}
	return sock;
}

int tcp_accept_server(int sock)
{
	struct sockaddr_in maddr;
	int sock2;
	socklen_t addrlen;
#ifdef DEBUG
	test_msg("Waiting for connection..........\n");
#endif
	addrlen = sizeof(maddr);
	sock2 = accept(sock, (struct sockaddr *)&maddr, &addrlen);

	if (sock2 == -1) {
		pr_perror("accept() failed");
		return -1;
	}

#ifdef DEBUG
	test_msg("Connection!!\n");
#endif
	return sock2;
}

int tcp_init_client(int family, char *servIP, unsigned short servPort)
{
	int sock;

	if ((sock = socket(family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		pr_perror("can't create socket");
		return -1;
	}

	return tcp_init_client_with_fd(sock, family, servIP, servPort);
}

int tcp_init_client_with_fd(int sock, int family, char *servIP, unsigned short servPort)
{
	union sockaddr_inet servAddr;

	/* Construct the server address structure */
	memset(&servAddr, 0, sizeof(servAddr));
	if (family == AF_INET) {
		servAddr.v4.sin_family = AF_INET;
		servAddr.v4.sin_port = htons(servPort);
		inet_pton(AF_INET, servIP, &servAddr.v4.sin_addr);
	} else {
		servAddr.v6.sin6_family = AF_INET6;
		servAddr.v6.sin6_port = htons(servPort);
		inet_pton(AF_INET6, servIP, &servAddr.v6.sin6_addr);
	}
	if (connect(sock, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0) {
		pr_perror("can't connect to server");
		return -1;
	}
	return sock;
}
