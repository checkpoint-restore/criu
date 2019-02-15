#include <poll.h>
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

#include <sys/types.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>


int main(int argc, char **argv)
{
	struct pollfd poll_set[1];
	int port = 9990;
	int fd_s, fd_c, fd;
	int ret;

	test_init(argc, argv);

	fd_s = tcp_init_server(ZDTM_FAMILY, &port);
	if (fd_s < 0)
		return -1;

	if (set_nonblock(fd_s, true)) {
		pr_perror("setting O_NONBLOCK failed");
		return -1;
	}

	fd_c = tcp_init_client(ZDTM_FAMILY, "localhost", port);
	if (fd_c < 0)
		return -1;

	test_daemon();
	test_waitsig();

	if (close(fd_c)) {
		fail("Unable to close a client socket");
		return 1;
	}

	fd = tcp_accept_server(fd_s);
	if (fd >= 0)
		close(fd);

	fd_c = tcp_init_client(ZDTM_FAMILY, "localhost", port);
	if (fd_c < 0) {
		fail("Unable to create a client socket");
		return -1;
	}

	memset(poll_set, '\0', sizeof(poll_set));
	poll_set[0].fd = fd_s;
	poll_set[0].events = POLLIN;
	ret = poll(poll_set, 1, -1);
	if (ret < 0) {
		pr_perror("poll() failed");
		return 1;
	}

	fd = tcp_accept_server(fd_s);
	if (fd < 0) {
		fail("Unable to accept a new connection");
		return 1;
	}
	close(fd);

	close(fd_c);
	close(fd_s);

	pass();
	return 0;
}
