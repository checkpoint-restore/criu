#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>  /* for sockaddr_in and inet_ntoa() */

#include "zdtmtst.h"

int tcp_init_server(int *port)
{
	struct sockaddr_in addr;
	int sock;
	int yes = 1, ret;

	memset(&addr,0,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("0.0.0.0");
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == -1) {
		err ("socket() failed %m");
		return -1;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ) {
		err("setsockopt() error");
		return -1;
	}

	while (1) {
		addr.sin_port = htons(*port);
		ret = bind(sock, (struct sockaddr *) &addr, sizeof(addr));

		/* crtools doesn't restore sock opts, so we need this hack */
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

int tcp_init_client(char *servIP, unsigned short servPort)
{
	int sock;
	struct sockaddr_in servAddr;

	if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		err("can't create socket %m");
		return -1;
	}
	/* Construct the server address structure */
	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sin_family      = AF_INET;
	servAddr.sin_addr.s_addr = inet_addr(servIP);
	servAddr.sin_port        = htons(servPort);
	if (connect(sock, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0) {
		err("can't connect to server %m");
		return -1;
	}
	return sock;
}
