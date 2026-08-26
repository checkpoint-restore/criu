#include "zdtmtst.h"

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

const char *test_doc = "Check closed tcp sockets\n";
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
#include <signal.h>

static int port = 8880;

union sockaddr_inet {
	struct sockaddr addr;
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
};

#ifdef ZDTM_TCP_LAST_ACK
#define SOCCR_MARK 0xC114

static int block_incoming_port(int port)
{
	char cmd[512];

	if (ZDTM_FAMILY == AF_INET)
		snprintf(cmd, sizeof(cmd),
			 "iptables -w -t filter -A INPUT -m mark ! --mark 0x%x --protocol tcp --dport %d -j DROP",
			 SOCCR_MARK, port);
	else
		snprintf(cmd, sizeof(cmd),
			 "ip6tables -w -t filter -A INPUT -m mark ! --mark 0x%x --protocol tcp --dport %d -j DROP",
			 SOCCR_MARK, port);

	return system(cmd);
}

static void unblock_incoming_port(int port)
{
	char cmd[512];

	if (ZDTM_FAMILY == AF_INET)
		snprintf(cmd, sizeof(cmd),
			 "iptables -w -t filter -D INPUT -m mark ! --mark 0x%x --protocol tcp --dport %d -j DROP 2>/dev/null || true",
			 SOCCR_MARK, port);
	else
		snprintf(cmd, sizeof(cmd),
			 "ip6tables -w -t filter -D INPUT -m mark ! --mark 0x%x --protocol tcp --dport %d -j DROP 2>/dev/null || true",
			 SOCCR_MARK, port);

	system(cmd);
}
#endif

int main(int argc, char **argv)
{
	int fd, fd_s, clt, sk;
	union sockaddr_inet src_addr, dst_addr, addr;
	socklen_t aux;
	char c = 5;

	test_init(argc, argv);
	signal(SIGPIPE, SIG_IGN);

	sk = socket(ZDTM_FAMILY, SOCK_STREAM, 0);
	if (sk < 0) {
		pr_perror("socket");
		return 1;
	}

	if ((fd_s = tcp_init_server(ZDTM_SRV_FAMILY, &port)) < 0) {
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

	shutdown(clt, SHUT_WR);

#ifdef ZDTM_TCP_LAST_ACK
	if (block_incoming_port(port))
		return -1;
#endif

	shutdown(fd, SHUT_WR);

	if (ZDTM_FAMILY == AF_INET)
		aux = sizeof(struct sockaddr_in);
	else if (ZDTM_FAMILY == AF_INET6)
		aux = sizeof(struct sockaddr_in6);
	else
		return 1;

	if (getsockopt(clt, SOL_SOCKET, SO_PEERNAME, &dst_addr, &aux)) {
		pr_perror("SO_PEERNAME");
		return 1;
	}
	if (getsockname(clt, &src_addr.addr, &aux)) {
		pr_perror("getsockname");
		return 1;
	}

	test_daemon();
	test_waitsig();

#ifdef ZDTM_TCP_LAST_ACK
	unblock_incoming_port(port);
#endif

	if (read(fd, &c, 1) != 0) {
		fail("read");
		return 1;
	}
	if (read(clt, &c, 1) != 0) {
		fail("read");
		return 1;
	}
	if (write(clt, &c, 1) != -1) {
		fail("write");
		return 1;
	}
	if (write(fd, &c, 1) != -1) {
		fail("write");
		return 1;
	}

	if (getsockopt(clt, SOL_SOCKET, SO_PEERNAME, &addr, &aux)) {
		pr_perror("SO_PEERNAME");
		return 1;
	}
	if (memcmp(&addr, &dst_addr, aux)) {
		pr_err("A destination address mismatch\n");
		return 1;
	}

	if (getsockname(clt, &addr.addr, &aux)) {
		pr_perror("getsockname");
		return 1;
	}
	if (memcmp(&addr, &src_addr, aux)) {
		pr_err("A source address mismatch\n");
		return 1;
	}

	pass();
	return 0;
}
