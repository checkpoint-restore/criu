#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "zdtmtst.h"

const char *test_doc = "Check that SO_BUF_LOCK option dumped";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

#ifndef SO_BUF_LOCK
#define SO_BUF_LOCK 72
#endif

#define NSOCK 4

int main(int argc, char **argv)
{
	int sock[NSOCK];
	uint32_t val[NSOCK];
	int ret, i;
	int exit_code = 1;

	test_init(argc, argv);

	for (i = 0; i < NSOCK; i++) {
		sock[i] = -1;
		val[i] = i;
	}

	for (i = 0; i < NSOCK; i++) {
		sock[i] = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (sock[i] < 0) {
			pr_perror("can't create socket %d", i);
			goto err;
		}

		ret = setsockopt(sock[i], SOL_SOCKET, SO_BUF_LOCK, &val[i], sizeof(val[i]));
		if (ret < 0) {
			pr_perror("can't set SO_BUF_LOCK (%u) on socket %d", val[i], i);
			goto err;
		}
	}

	test_daemon();
	test_waitsig();

	for (i = 0; i < NSOCK; i++) {
		uint32_t tmp;
		socklen_t len;

		len = sizeof(tmp);
		ret = getsockopt(sock[i], SOL_SOCKET, SO_BUF_LOCK, &tmp, &len);
		if (ret < 0) {
			pr_perror("can't get SO_BUF_LOCK from socket %d", i);
			goto err;
		}

		if (tmp != val[i]) {
			fail("SO_BUF_LOCK missmatch %u != %u", tmp, val[i]);
			goto err;
		}
	}

	pass();
	exit_code = 0;
err:
	for (i = 0; i < NSOCK; i++)
		close(sock[i]);

	return exit_code;
}
