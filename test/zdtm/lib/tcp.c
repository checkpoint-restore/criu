#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>  /* for sockaddr_in and inet_ntoa() */

#include "zdtmtst.h"

union sockaddr_inet {
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
};

int tcp_init_server(int family, int *port)
{
	union sockaddr_inet addr;
	int sock;
	int yes = 1, ret;

	memset(&addr,0,sizeof(addr));
	if (family == AF_INET) {
		addr.v4.sin_family = family;
		inet_pton(family, "0.0.0.0", &(addr.v4.sin_addr));
	} else if (family == AF_INET6){
		addr.v6.sin6_family = family;
		inet_pton(family, "::0", &(addr.v6.sin6_addr));
	} else
		return -1;

	sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
	if (sock == -1) {
		err ("socket() failed %m");
		return -1;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ) {
		err("setsockopt() error");
		return -1;
	}

	while (1) {
		if (family == AF_INET)
			addr.v4.sin_port = htons(*port);
		else if (family == AF_INET6)
			addr.v6.sin6_port = htons(*port);

		ret = bind(sock, (struct sockaddr *) &addr, sizeof(addr));

		/* criu doesn't restore sock opts, so we need this hack */
		if (ret == -1 && errno == EADDRINUSE) {
			test_msg("The port %d is already in use.\n", *port);
			(*port)++;
			continue;
		}
		break;
	}

	if (ret == -1) {
		err ("bind() failed %m");
		return -1;
	}

	if (listen(sock, 1) == -1) {
		err ("listen() failed %m");
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
	test_msg ("Waiting for connection..........\n");
#endif
	addrlen = sizeof(maddr);
	sock2 = accept(sock,(struct sockaddr *) &maddr, &addrlen);

	if (sock2 == -1) {
		err ("accept() failed %m");
		return -1;
	}

#ifdef DEBUG
	test_msg ("Connection!!\n");
#endif
	return sock2;
}

int tcp_init_client(int family, char *servIP, unsigned short servPort)
{
	int sock;
	union sockaddr_inet servAddr;

	if ((sock = socket(family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		err("can't create socket %m");
		return -1;
	}
	/* Construct the server address structure */
	memset(&servAddr, 0, sizeof(servAddr));
	if (family == AF_INET) {
		servAddr.v4.sin_family      = AF_INET;
		servAddr.v4.sin_port        = htons(servPort);
		inet_pton(AF_INET, servIP, &servAddr.v4.sin_addr);
	} else {
		servAddr.v6.sin6_family      = AF_INET6;
		servAddr.v6.sin6_port        = htons(servPort);
		inet_pton(AF_INET6, servIP, &servAddr.v6.sin6_addr);
	}
	if (connect(sock, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0) {
		err("can't connect to server %m");
		return -1;
	}
	return sock;
}
