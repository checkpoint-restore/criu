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

const char *test_doc = "Check sockets in TCP_FIN_WAIT* states\n";
const char *test_author = "Andrey Vagin <avagin@parallels.com";

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

static int port = 8880;

#define TEST_MSG "Hello World!"
#define BUF_SIZE 4096

int fill_sock_buf(int fd)
{
	int flags;
	int size;
	int ret;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		pr_perror("Can't get flags");
		return -1;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		pr_perror("Can't set flags");
		return -1;
	}

	size = 0;
	while (1) {
		char zdtm[] = "zdtm test packet";
		ret = write(fd, zdtm, sizeof(zdtm));
		if (ret == -1) {
			if (errno == EAGAIN)
				break;
			pr_perror("write");
			return -1;
		}
		size += ret;
	}

	if (fcntl(fd, F_SETFL, flags) == -1) {
		pr_perror("Can't set flags");
		return -1;
	}

	test_msg("snd_size = %d\n", size);

	return size;
}

static int clean_sk_buf(int fd)
{
	int size, ret;
	char buf[BUF_SIZE];

	size = 0;
	while (1) {
		ret = read(fd, buf, sizeof(buf));
		if (ret == -1) {
			pr_perror("read");
			return -11;
		}

		if (ret == 0)
			break;

		size += ret;
	}

	test_msg("rcv_size = %d\n", size);

	return size;
}

int main(int argc, char **argv)
{
	char *newns = getenv("ZDTM_NEWNS");
	int fd, fd_s, ctl_fd;
	pid_t extpid;
	int pfd[2];
	int ret, snd_size = 0;
	char buf[BUF_SIZE];

	if (newns)
		test_init(argc, argv);

	if (pipe(pfd)) {
		pr_perror("pipe() failed");
		return 1;
	}

	extpid = fork();
	if (extpid < 0) {
		pr_perror("fork() failed");
		return 1;
	} else if (extpid == 0) {
		int size = 0;
		char c;

		if (!newns)
			test_ext_init(argc, argv);

		close(pfd[1]);
		if (read(pfd[0], &port, sizeof(port)) != sizeof(port)) {
			pr_perror("Can't read port");
			return 1;
		}

		fd = tcp_init_client(ZDTM_FAMILY, "127.0.0.1", port);
		if (fd < 0)
			return 1;
		write(fd, TEST_MSG, 2);

		ctl_fd = tcp_init_client(ZDTM_FAMILY, "127.0.0.1", port);
		if (ctl_fd < 0)
			return 1;

		if (read(ctl_fd, &c, 1) != 0) {
			pr_perror("read");
			return 1;
		}

		if (write(fd, &TEST_MSG[2], sizeof(TEST_MSG) - 2) != sizeof(TEST_MSG) - 2) {
			pr_perror("write");
			return 1;
		}

		if (shutdown(fd, SHUT_WR) == -1) {
			pr_perror("shutdown");
			return 1;
		}

		size = clean_sk_buf(fd);
		if (size < 0)
			return 1;

		write(ctl_fd, &size, sizeof(size));
		close(fd);

		return 0;
	}

	if (!newns)
		test_init(argc, argv);

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

	ctl_fd = tcp_accept_server(fd_s);
	if (ctl_fd < 0) {
		pr_err("can't accept client connection\n");
		return 1;
	}

#if !defined(ZDTM_TCP_FIN_WAIT2)
	snd_size = fill_sock_buf(fd);
	if (snd_size <= 0)
		return 1;
#endif

	if (shutdown(fd, SHUT_WR) == -1) {
		pr_perror("shutdown");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (shutdown(ctl_fd, SHUT_WR) == -1) {
		pr_perror("shutdown");
		return 1;
	}

	if (recv(fd, buf, sizeof(buf), MSG_WAITALL) != sizeof(TEST_MSG) || strncmp(buf, TEST_MSG, sizeof(TEST_MSG))) {
		pr_perror("recv: expected %s, got %s", TEST_MSG, buf);
		return 1;
	}

	if (read(ctl_fd, &ret, sizeof(ret)) != sizeof(ret)) {
		pr_perror("read");
		return 1;
	}

	if (ret != snd_size) {
		fail("The parent sent %d bytes, but the child received %d bytes", snd_size, ret);
		return 1;
	}

	pass();
	return 0;
}
