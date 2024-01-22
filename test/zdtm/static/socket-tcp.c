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

const char *test_doc = "Check, that a TCP connection can be restored\n";
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

#define BUF_SIZE 4096

int read_data(int fd, unsigned char *buf, int size)
{
	int cur = 0;
	int ret;
	while (cur != size) {
		ret = read(fd, buf + cur, size - cur);
		if (ret <= 0)
			return -1;
		cur += ret;
	}

	return 0;
}

int write_data(int fd, const unsigned char *buf, int size)
{
	int cur = 0;
	int ret;

	while (cur != size) {
		ret = write(fd, buf + cur, size - cur);
		if (ret <= 0)
			return -1;
		cur += ret;
	}

	return 0;
}

int main(int argc, char **argv)
{
	unsigned char buf[BUF_SIZE];
	int fd, fd_s;
	pid_t extpid;
	uint32_t crc;
	int pfd[2];
	int val;
	socklen_t optlen;

#ifdef ZDTM_IPT_CONNTRACK
	if (unshare(CLONE_NEWNET)) {
		pr_perror("unshare");
		return 1;
	}
	if (system("ip link set up dev lo"))
		return 1;

	if (system("iptables-legacy -w -A INPUT -i lo -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT"))
		return 1;
	if (system("iptables-legacy -w -A INPUT -j DROP"))
		return 1;

#endif

#ifdef ZDTM_NFT_CONNTRACK
	if (unshare(CLONE_NEWNET)) {
		pr_perror("unshare");
		return 1;
	}
	if (system("ip link set up dev lo"))
		return 1;

	if (system("nft add table ip filter"))
		return 1;
	if (system("nft 'add chain ip filter INPUT { type filter hook input priority 0 ; }'"))
		return 1;
	if (system("nft add rule ip filter INPUT iifname \"lo\" ip protocol tcp ct state new,established counter accept"))
		return 1;
	if (system("nft add rule ip filter INPUT counter drop"))
		return 1;

#endif

#ifdef ZDTM_TCP_LOCAL
	test_init(argc, argv);
#endif

	if (pipe(pfd)) {
		pr_perror("pipe() failed");
		return 1;
	}

	extpid = fork();
	if (extpid < 0) {
		pr_perror("fork() failed");
		return 1;
	} else if (extpid == 0) {
#ifndef ZDTM_TCP_LOCAL
		test_ext_init(argc, argv);
#endif

		close(pfd[1]);
		if (read(pfd[0], &port, sizeof(port)) != sizeof(port)) {
			pr_perror("Can't read port");
			return 1;
		}

		fd = tcp_init_client(ZDTM_FAMILY, "localhost", port);
		if (fd < 0)
			return 1;

#ifdef STREAM
		while (1) {
			if (read_data(fd, buf, BUF_SIZE)) {
				pr_perror("read less then have to");
				return 1;
			}
			if (datachk(buf, BUF_SIZE, &crc))
				return 2;

			datagen(buf, BUF_SIZE, &crc);
			if (write_data(fd, buf, BUF_SIZE)) {
				pr_perror("can't write");
				return 1;
			}
		}
#else
		if (read_data(fd, buf, BUF_SIZE)) {
			pr_perror("read less then have to");
			return 1;
		}
		if (datachk(buf, BUF_SIZE, &crc))
			return 2;

		datagen(buf, BUF_SIZE, &crc);
		if (write_data(fd, buf, BUF_SIZE)) {
			pr_perror("can't write");
			return 1;
		}
#endif
		return 0;
	}

#ifndef ZDTM_TCP_LOCAL
	test_init(argc, argv);
#endif

	if ((fd_s = tcp_init_server(ZDTM_SRV_FAMILY, &port)) < 0) {
		pr_err("initializing server failed\n");
		return 1;
	}

	close(pfd[0]);
	if (write(pfd[1], &port, sizeof(port)) != sizeof(port)) {
		pr_perror("Can't send port");
		return 1;
	}
	close(pfd[1]);

	/*
	 * parent is server of TCP connection
	 */
	fd = tcp_accept_server(fd_s);
	if (fd < 0) {
		pr_err("can't accept client connection\n");
		return 1;
	}

	val = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val))) {
		pr_perror("setsockopt");
		return 1;
	}

	test_daemon();
#ifdef STREAM
	while (test_go()) {
		datagen(buf, BUF_SIZE, &crc);
		if (write_data(fd, buf, BUF_SIZE)) {
			pr_perror("can't write");
			return 1;
		}

		if (read_data(fd, buf, BUF_SIZE)) {
			pr_perror("read less then have to");
			return 1;
		}
		if (datachk(buf, BUF_SIZE, &crc))
			return 2;
	}
	kill(extpid, SIGKILL);
#else
	test_waitsig();

	datagen(buf, BUF_SIZE, &crc);
	if (write_data(fd, buf, BUF_SIZE)) {
		pr_perror("can't write");
		return 1;
	}

	if (read_data(fd, buf, BUF_SIZE)) {
		pr_perror("read less then have to");
		return 1;
	}
	if (datachk(buf, BUF_SIZE, &crc))
		return 2;
#endif
	optlen = sizeof(val);
	if (getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, &optlen)) {
		pr_perror("getsockopt");
		return 1;
	}
	if (val != 1) {
		fail("SO_REUSEADDR are not set for %d", fd);
		return 1;
	}

	pass();
	return 0;
}
