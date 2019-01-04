#include "zdtmtst.h"

#ifdef ZDTM_IPV4V6
#define ZDTM_FAMILY AF_INET
#elif defined(ZDTM_IPV6)
#define ZDTM_FAMILY AF_INET6
#else
#define ZDTM_FAMILY AF_INET
#endif

const char *test_doc = "Check that in-flight TCP connections are ignored\n";
const char *test_author = "Radostin Stoyanov <rstoyanov1@gmail.com>";

/* Description:
 * Initialise server and client tcp sockets and verify that
 * in-flight TCP connections are ignored.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <linux/types.h>
#include <netinet/tcp.h>

#define PORT 1234
#define HOST "127.0.0.1"

static int check_socket_state(int sk, int state)
{
		int err;
		struct {
				__u8    tcpi_state;
		} info;
		socklen_t len = sizeof(info);

		err = getsockopt(sk, IPPROTO_TCP, TCP_INFO, (void *)&info, &len);
		if (err != 0) {
				pr_perror("Can't get socket state\n");
				return -1;
		} else if (info.tcpi_state != state) {
				fail("Invalid socket state (%i)\n", (int)info.tcpi_state);
				return -1;
		}

		return 0;
}

int open_socket()
{
	int fd;
	fd = socket(ZDTM_FAMILY, SOCK_STREAM, 0);
	if (fd < 0) {
		fail("Failed to open socket\n");
		return -1;
	}
	return fd;
}

int server()
{
	 int fd_s;
	 struct sockaddr_in serv_addr;

	 fd_s = open_socket();
	 if (fd_s < 0)
		return -1;

	 bzero((char *) &serv_addr, sizeof(serv_addr));
	 serv_addr.sin_family = ZDTM_FAMILY;
	 serv_addr.sin_addr.s_addr = INADDR_ANY;
	 serv_addr.sin_port = htons(PORT);

	 if (bind(fd_s, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		fail("Failed to bind");
		return -1;
	 }

	 listen(fd_s, 1);

	 /* Listen but do not accept connect()-ed TCP connection. */

	 return fd_s;
}

int client()
{
	int fd_c;
	struct sockaddr_in serv_addr;
	struct hostent *server;

	fd_c = open_socket();
	if (fd_c < 0)
		return -1;

	server = gethostbyname(HOST);
	if (server == NULL) {
		fail("Failed to get host by name\n");
		return -1;
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = ZDTM_FAMILY;
	bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
	serv_addr.sin_port = htons(PORT);
	if (connect(fd_c,(struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		fail("Failed to get host by name\n");
		return -1;
	}

   return fd_c;
}

int main(int argc, char **argv)
{
	int fd_s;
	int fd_c;

	test_init(argc, argv);

	fd_s = server();
	if (fd_s < 0) {
		fail("Failed to initialize server\n");
		return -1;
	}

	fd_c = client();
	if (fd_c < 0) {
		fail("Failed to initialize client\n");
		return -1;
	}

	if (check_socket_state(fd_s, TCP_LISTEN)) {
		fail("Server socket state before restore isn't TCP_LISTEN\n");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (check_socket_state(fd_s, TCP_LISTEN)) {
		fail("Server socket state after restore isn't TCP_LISTEN\n");
		return 1;
	}

	close(fd_s);
	close(fd_c);

	pass();
	return 0;
}
