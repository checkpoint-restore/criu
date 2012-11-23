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

static int fill_sock_buf(int fd)
{
	int flags;
	int size;
	int ret;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		err("Can't get flags");
		return -1;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		err("Can't set flags");
		return -1;
	}

	size = 0;
	while (1) {
		char zdtm[] = "zdtm test packet";
		ret = write(fd, zdtm, sizeof(zdtm));
		if (ret == -1) {
			if (errno == EAGAIN)
				break;
			err("write");
			return -1;
		}
		size += ret;
	}

	if (fcntl(fd, F_SETFL, flags) == -1) {
		err("Can't set flags");
		return -1;
	}

	test_msg("snd_size = %d\n", size);

	return size;
}

static int clean_sk_buf(fd)
{
	int size, ret;
	char buf[BUF_SIZE];

	size = 0;
	while (1) {
		ret = read(fd, buf, sizeof(buf));
		if (ret == -1) {
			err("read");
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
	int fd, fd_s, ctl_fd;
	pid_t extpid;
	int pfd[2];
	int sk_bsize;
	int ret, snd_size, rcv_size;

	if (pipe(pfd)) {
		err("pipe() failed");
		return 1;
	}

	extpid = fork();
	if (extpid < 0) {
		err("fork() failed");
		return 1;
	} else if (extpid == 0) {
		int size;
		char c;

		test_ext_init(argc, argv);

		close(pfd[1]);
		if (read(pfd[0], &port, sizeof(port)) != sizeof(port)) {
			err("Can't read port\n");
			return 1;
		}

		fd = tcp_init_client(ZDTM_FAMILY, "127.0.0.1", port);
		if (fd < 0)
			return 1;

		ctl_fd = tcp_init_client(ZDTM_FAMILY, "127.0.0.1", port);
		if (fd < 0)
			return 1;

		size = fill_sock_buf(fd);
		if (size <= 0)
			return 1;

		if (write(ctl_fd, &size, sizeof(size)) != sizeof(size)) {
			err("write");
			return 1;
		}

		if (read(ctl_fd, &c, 1) != 0) {
			err("read");
			return 1;
		}

		if (shutdown(fd, SHUT_WR) == -1) {
			err("shutdown");
			return 1;
		}

		size = clean_sk_buf(fd);
		if (size < 0)
			return 1;

		write(ctl_fd, &size, sizeof(size));
		close(fd);

		return 0;
	}

	test_init(argc, argv);

	if ((fd_s = tcp_init_server(ZDTM_FAMILY, &port)) < 0) {
		err("initializing server failed");
		return 1;
	}

	close(pfd[0]);
	if (write(pfd[1], &port, sizeof(port)) != sizeof(port)) {
		err("Can't send port");
		return 1;
	}
	close(pfd[1]);

	/*
	 * parent is server of TCP connection
	 */
	fd = tcp_accept_server(fd_s);
	if (fd < 0) {
		err("can't accept client connection %m");
		return 1;
	}

	ctl_fd = tcp_accept_server(fd_s);
	if (ctl_fd < 0) {
		err("can't accept client connection %m");
		return 1;
	}

	sk_bsize = TCP_MAX_BUF;
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF,
			&sk_bsize, sizeof(sk_bsize)) == -1) {
		err("Can't set snd buf");
		return 1;
	}

	sk_bsize = TCP_MAX_BUF;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
			&sk_bsize, sizeof(sk_bsize)) == -1) {
		err("Can't set snd buf");
		return 1;
	}

	snd_size = fill_sock_buf(fd);
	if (snd_size <= 0)
		return 1;

	if (read(ctl_fd, &ret, sizeof(ret)) != sizeof(ret)) {
		err("read");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (shutdown(ctl_fd, SHUT_WR) == -1) {
		err("shutdown");
		return 1;
	}

	if (shutdown(fd, SHUT_WR) == -1) {
		err("shutdown");
		return 1;
	}

	rcv_size = clean_sk_buf(fd);

	if (ret != rcv_size) {
		fail("The child sent %d bytes, but the parent recieved %d bytes\n", rcv_size, ret);
		return 1;
	}

	if (read(ctl_fd, &ret, sizeof(ret)) != sizeof(ret)) {
		err("read");
		return 1;
	}

	if (ret != snd_size) {
		fail("The parent sent %d bytes, but the child recieved %d bytes\n", snd_size, ret);
		return 1;
	}

	pass();
	return 0;
}
