#include "zdtmtst.h"

const char *test_doc = "static test for AIO\n";
const char *test_author = "Andrew Vagin <avagin@parallels.com>";

/* Description:
 * Create two tcp socket, server send asynchronous request on
 * read data and client write data after migration
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <aio.h>
#include <sys/wait.h>
#include <netinet/tcp.h>

static int port = 8880;

#define BUF_SIZE 1024

int main(int argc, char **argv)
{
	char buf[BUF_SIZE];
	int fd, fd_s;
	struct aiocb aiocb;
	int status;
	pid_t pid;
	int ret, res;
	const struct aiocb *aioary[1];
	task_waiter_t child_waiter;

	test_init(argc, argv);

	task_waiter_init(&child_waiter);

	if ((fd_s = tcp_init_server(AF_INET, &port)) < 0) {
		pr_err("initializing server failed\n");
		return 1;
	}

	pid = test_fork();
	if (pid < 0) {
		pr_perror("fork failed");
		return 1;
	}

	if (pid == 0) {
		/*
		 * Chiled is client of TCP connection
		 */
		close(fd_s);
		fd = tcp_init_client(AF_INET, "127.0.0.1", port);
		if (fd < 0)
			return 1;

		memset(&aiocb, 0, sizeof(struct aiocb));
		aiocb.aio_fildes = fd;
		aiocb.aio_buf = buf;
		aiocb.aio_nbytes = BUF_SIZE;
		ret = aio_read(&aiocb);
		if (ret < 0) {
			pr_perror("aio_read failed");
			return 1;
		}

		task_waiter_complete_current(&child_waiter);

		/* Wait for request completion */
		aioary[0] = &aiocb;
		ret = aio_error(&aiocb);
#ifdef DEBUG
		test_msg(".");
#endif
		res = 0;
	again:
		if (aio_suspend(aioary, 1, NULL) < 0 && errno != EINTR) {
			pr_perror("aio_suspend failed");
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
			pr_err("Error at aio_error(): %s\n", strerror(ret));
			res = 1;
		}

		if (aio_return(&aiocb) != BUF_SIZE) {
			pr_perror("Error at aio_return()");
			res = 1;
		}

		close(fd);
		return res;
	}

	/*
	 * parent is server of TCP connection
	 */
	fd = tcp_accept_server(fd_s);
	close(fd_s);
	if (fd < 0) {
		pr_err("can't accept client connection\n");
		goto error;
	}

	task_waiter_wait4(&child_waiter, pid);

	test_daemon();
	test_waitsig();

	if (write(fd, buf, BUF_SIZE) < BUF_SIZE) {
		pr_perror("can't write");
		goto error;
	}
	close(fd);

	if (wait(&status) < 0) {
		pr_perror("wait failed");
		goto error;
	}

	if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
		pr_err("child failed with exit code %d\n", WEXITSTATUS(status));
		return 1;
	}

	pass();
	return 0;
error:
	kill(pid, SIGKILL);
	wait(&status);
	return -1;
}
