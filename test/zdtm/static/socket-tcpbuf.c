#include "zdtmtst.h"

#ifdef ZDTM_IPV6
#define ZDTM_FAMILY AF_INET6
#else
#define ZDTM_FAMILY AF_INET
#endif

const char *test_doc = "Check full tcp buffers with custom sizes\n";
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

#define BUF_SIZE 4096
#define TCP_MAX_BUF (100 << 20)

static void read_safe(int fd, void *buf, size_t size)
{
	if (read(fd, buf, size) != size) {
		pr_perror("Unable to read from %d", fd);
		exit(1);
	}
}

static void write_safe(int fd, void *buf, size_t size)
{
	if (write(fd, buf, size) != size) {
		pr_perror("Unable to write to %d", fd);
		exit(1);
	}
}

static int fill_sock_buf(int fd)
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

	return size;
}

static int clean_sk_buf(int fd, int limit)
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

		if (limit && size >= limit)
			break;
	}

	return size;
}

int main(int argc, char **argv)
{
	int fd, fd_s, ctl_fd;
	pid_t extpid;
	int pfd[2];
	int sk_bsize;
	int ret, snd, snd_size, rcv_size = 0, rcv_buf_size;

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
		int size;
		char c;

#ifndef ZDTM_TCP_LOCAL
		test_ext_init(argc, argv);
#endif

		close(pfd[1]);
		read_safe(pfd[0], &port, sizeof(port));

		fd = tcp_init_client(ZDTM_FAMILY, "127.0.0.1", port);
		if (fd < 0)
			return 1;

		ctl_fd = tcp_init_client(ZDTM_FAMILY, "127.0.0.1", port);
		if (fd < 0)
			return 1;

		snd_size = fill_sock_buf(fd);
		if (snd_size <= 0)
			return 1;

		write_safe(ctl_fd, &snd_size, sizeof(snd_size));

		read_safe(ctl_fd, &rcv_buf_size, sizeof(rcv_buf_size));

		while (1) {
			/* heart beat */
			read_safe(ctl_fd, &ret, sizeof(ret));
			if (ret < 0)
				break;
			rcv_buf_size += ret;

			snd = fill_sock_buf(fd);
			if (snd < 0)
				return -1;
			snd_size += snd;

			if (rcv_buf_size / 2) {
				ret = clean_sk_buf(fd, rcv_buf_size / 2);
				if (ret <= 0)
					return 1;
			} else
				ret = 0;

			rcv_buf_size -= ret;
			rcv_size += ret;

			write_safe(ctl_fd, &snd, sizeof(snd));
		}

		read_safe(ctl_fd, &ret, sizeof(ret));
		rcv_buf_size += ret;

		write_safe(ctl_fd, &snd_size, sizeof(snd_size));

		if (read(ctl_fd, &c, 1) != 0) {
			pr_perror("read");
			return 1;
		}

		if (shutdown(fd, SHUT_WR) == -1) {
			pr_perror("shutdown");
			return 1;
		}

		size = clean_sk_buf(fd, 0);
		if (size < 0)
			return 1;

		if (size != rcv_buf_size) {
			fail("the received buffer contains only %d bytes (%d)\n", size, rcv_buf_size);
		}

		rcv_size += size;

		write_safe(ctl_fd, &rcv_size, sizeof(rcv_size));
		close(fd);

		return 0;
	}

#ifndef ZDTM_TCP_LOCAL
	test_init(argc, argv);
#endif

	if ((fd_s = tcp_init_server(ZDTM_FAMILY, &port)) < 0) {
		pr_err("initializing server failed\n");
		return 1;
	}

	close(pfd[0]);
	write_safe(pfd[1], &port, sizeof(port));
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

	sk_bsize = TCP_MAX_BUF;
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF,
			&sk_bsize, sizeof(sk_bsize)) == -1) {
		pr_perror("Can't set snd buf");
		return 1;
	}

	sk_bsize = TCP_MAX_BUF;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
			&sk_bsize, sizeof(sk_bsize)) == -1) {
		pr_perror("Can't set snd buf");
		return 1;
	}

	snd_size = fill_sock_buf(fd);
	if (snd_size <= 0)
		return 1;

	read_safe(ctl_fd, &rcv_buf_size, sizeof(rcv_buf_size));

	write_safe(ctl_fd, &snd_size, sizeof(snd_size));

	test_daemon();

	snd = 0;
	while (test_go()) {
		/* heart beat */
		if (rcv_buf_size / 2) {
			ret = clean_sk_buf(fd, rcv_buf_size / 2);
			if (ret <= 0)
				return 1;
		} else
			ret = 0;

		rcv_size += ret;
		rcv_buf_size -= ret;

		write_safe(ctl_fd, &snd, sizeof(snd));
		read_safe(ctl_fd, &ret, sizeof(ret));

		rcv_buf_size += ret;

		snd = fill_sock_buf(fd);
		if (snd < 0)
			return -1;
		snd_size += snd;
	}

	ret = -1;
	write_safe(ctl_fd, &ret, sizeof(ret));
	write_safe(ctl_fd, &snd, sizeof(ret));
	read_safe(ctl_fd, &snd, sizeof(snd));

	if (shutdown(ctl_fd, SHUT_WR) == -1) {
		pr_perror("shutdown");
		return 1;
	}

	if (shutdown(fd, SHUT_WR) == -1) {
		pr_perror("shutdown");
		return 1;
	}

	ret = clean_sk_buf(fd, 0);
	if (ret != rcv_buf_size) {
		fail("the received buffer contains only %d bytes (%d)\n", ret, rcv_buf_size);
	}
	rcv_size += ret;

	if (snd != rcv_size) {
		fail("The child sent %d bytes, but the parent received %d bytes\n", rcv_buf_size, rcv_size);
		return 1;
	}

	read_safe(ctl_fd, &ret, sizeof(ret));

	if (ret != snd_size) {
		fail("The parent sent %d bytes, but the child received %d bytes\n", snd_size, ret);
		return 1;
	}

	pass();
	return 0;
}
