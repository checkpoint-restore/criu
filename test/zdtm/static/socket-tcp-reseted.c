
#include "zdtmtst.h"
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h> /* for sockaddr_in and inet_ntoa() */
#include <stdlib.h>
#include <sys/wait.h>
#include <signal.h>

#ifdef ZDTM_IPV4V6
#define ZDTM_FAMILY	AF_INET
#define ZDTM_SRV_FAMILY AF_INET6
#elif defined(ZDTM_IPV6)
#define ZDTM_FAMILY	AF_INET6
#define ZDTM_SRV_FAMILY AF_INET6
#else
#define ZDTM_FAMILY	AF_INET
#define ZDTM_SRV_FAMILY AF_INET
#endif

const char *test_doc = "Check, that a reseted TCP connection can be restored\n";
const char *test_author = "Andrey Vagin <avagin@parallels.com";

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <sched.h>
#include <netinet/tcp.h>

static int port = 8880;

int main(int argc, char **argv)
{
	int fd, fd_s, clt;
	char cmd[4096], buf[10];

	test_init(argc, argv);
	signal(SIGPIPE, SIG_IGN);

	if ((fd_s = tcp_init_server(ZDTM_SRV_FAMILY, &port)) < 0) {
		pr_err("initializing server failed\n");
		return 1;
	}

	clt = tcp_init_client(ZDTM_FAMILY, "localhost", port);
	if (clt < 0) {
		pr_perror("Unable to create a client socket");
		return 1;
	}

	/*
	* parent is server of TCP connection
	*/
	fd = tcp_accept_server(fd_s);
	if (fd < 0) {
		pr_err("can't accept client connection\n");
		return 1;
	}
	if (write(clt, "asd", 3) != 3) {
		pr_perror("Unable to write into a socket");
		return 1;
	}
	snprintf(cmd, sizeof(cmd),
		 "iptables -w -t filter --protocol tcp -A INPUT --dport %d -j REJECT --reject-with tcp-reset", port);
	if (system(cmd))
		return 1;

	if (write(fd, "asdas", 5) == -1) {
		pr_perror("Unable to write into a socket");
		return 1;
	}

	snprintf(cmd, sizeof(cmd),
		 "iptables -w -t filter --protocol tcp -D INPUT --dport %d -j REJECT --reject-with tcp-reset", port);
	if (system(cmd))
		return 1;

	test_daemon();
	test_waitsig();

	if (read(fd, buf, sizeof(buf)) != 3) {
		fail("Unable to read data from a socket");
		return 1;
	}

	if (write(fd, buf, 3) != -1) {
		fail("Can write into a closed socket");
		return 1;
	}

	pass();
	return 0;
}
