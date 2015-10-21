#include "zdtmtst.h"

#ifdef ZDTM_IPV6
#define ZDTM_FAMILY AF_INET6
#else
#define ZDTM_FAMILY AF_INET
#endif

const char *test_doc = "static test for listening socket\n";
const char *test_author = "Stanislav Kinsbursky <skinsbursky@openvz.org>";

/* Description:
 * Create two tcp socket, server send asynchronous request on
 * read data and clietn write data after migration
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <wait.h>
#include <netinet/tcp.h>

static int port = 8880;

#define BUF_SIZE 1024

static void sig_hand(int signo) {}

int main(int argc, char **argv)
{
	unsigned char buf[BUF_SIZE];
	int fd, fd_s;
	int status;
	pid_t pid;
	int res;
	uint32_t crc;
	struct sigaction sa = {
		.sa_handler	= sig_hand,
		/* don't set SA_RESTART */
	};

	test_init(argc, argv);

	if ((fd_s = tcp_init_server(ZDTM_FAMILY, &port)) < 0) {
		pr_err("initializing server failed\n");
		return 1;
	}

	test_daemon();
	test_waitsig();

	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGCHLD, &sa, NULL))
		pr_perror("Can't set SIGCHLD handler");

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
		fd = tcp_init_client(ZDTM_FAMILY, "localhost", port);
		if (fd < 0)
			return 1;

		res = read(fd, buf, BUF_SIZE);
		close(fd);
		if (res != BUF_SIZE) {
			pr_perror("read less then have to: %d instead of %d", res, BUF_SIZE);
			return -1;
		}
		if (datachk(buf, BUF_SIZE, &crc))
			return -2;
		return 0;
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

	datagen(buf, BUF_SIZE, &crc);
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
