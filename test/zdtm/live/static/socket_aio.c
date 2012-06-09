#include "zdtmtst.h"

const char *test_doc = "static test for AIO\n";
const char *test_author = "Andrew Vagin <avagin@parallels.com>";

/* Description:
 * Create two tcp socket, server send asynchronous request on
 * read data and clietn write data after migration
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <aio.h>
#include <sys/socket.h>
#include <arpa/inet.h>  /* for sockaddr_in and inet_ntoa() */
#include <wait.h>

static int port = 8880;

int init_client(char *servIP, unsigned short servPort);
int accept_server(int sock);
int init_server();

#define BUF_SIZE 1024

int main(int argc, char **argv)
{
	char buf[BUF_SIZE];
	int fd, fd_s;
	struct aiocb aiocb;
	int status;
	pid_t pid;
	int ret, res;
	const struct aiocb   *aioary[1];

	test_init(argc, argv);

	if ((fd_s = init_server()) < 0) {
		err("initializing server failed");
		return 1;
	}

	pid = test_fork();
	if (pid < 0) {
		err("fork failed. Return %d %m", pid);
		return 1;
	}

	if (pid == 0) {
		/*
		 * Chiled is client of TCP connection
		 */
		close(fd_s);
		fd = init_client("127.0.0.1", port);
		if (fd < 0)
			return 1;

		memset(&aiocb, 0, sizeof(struct aiocb));
		aiocb.aio_fildes = fd;
		aiocb.aio_buf = buf;
		aiocb.aio_nbytes = BUF_SIZE;
		ret = aio_read(&aiocb);
		if (ret < 0) {
			err("aio_read failed %m");
			return 1;
		}

		/* Wait for request completion */
		aioary[0] = &aiocb;
		ret = aio_error(&aiocb);
#ifdef DEBUG
		test_msg(".");
#endif
		res = 0;
again:
		if (aio_suspend(aioary, 1, NULL) < 0 && errno != EINTR) {
			err("aio_suspend failed %m");
			res = 1;
		}

		ret = aio_error(&aiocb);
		if (!res && ret == EINPROGRESS) {
#ifdef DEBUG
			test_msg("restart aio_suspend\n");
#endif
			goto again;
		}
		if (ret != 0) {
			err("Error at aio_error() %s", strerror(ret));
			res = 1;
		}

		if (aio_return(&aiocb) != BUF_SIZE) {
			err("Error at aio_return() %m");
			res = 1;
		}

		close(fd);
		return res;
	}

	/*
	 * parent is server of TCP connection
	 */
	fd = accept_server(fd_s);
	close(fd_s);
	if (fd < 0) {
		err("can't accept client connection %m");
		goto error;
	}

	test_daemon();
	test_waitsig();

	if (write(fd, buf, BUF_SIZE) < BUF_SIZE) {
		err("can't write");
		goto error;
	}
	close(fd);


	if (wait(&status) < 0) {
		err("wait failed %m");
		goto error;
	}

	if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
		err("chiled failed. Return %d", WEXITSTATUS(status));
		return 1;
	}

	pass();
	return 0;
error:
	kill(pid, SIGKILL);
	wait(&status);
	return -1;
}

int init_server()
{
	struct sockaddr_in addr;
	int sock, ret;

	memset(&addr,0,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htons(INADDR_ANY);
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == -1) {
		err ("socket() failed %m");
		return -1;
	}

	while (1) {
		addr.sin_port = htons(port);
		ret = bind(sock, (struct sockaddr *) &addr, sizeof(addr));
		if (ret == -1 && errno == EADDRINUSE) {
			test_msg("The port %d is already in use.\n", port);
			port++;
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

int accept_server(int sock)
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

int init_client(char *servIP, unsigned short servPort)
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
