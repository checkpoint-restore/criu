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

#ifndef SOCK_SNDBUF_LOCK
#define SOCK_SNDBUF_LOCK 1
#endif
#ifndef SOCK_RCVBUF_LOCK
#define SOCK_RCVBUF_LOCK 2
#endif

#define BUFSIZE 16384

struct sk_opt {
	int type;
	uint32_t val;
	uint32_t lock;
} sk_opts[] = { { SO_BUF_LOCK, 0, 0 },
		{ SO_BUF_LOCK, SOCK_SNDBUF_LOCK, SOCK_SNDBUF_LOCK },
		{ SO_BUF_LOCK, SOCK_RCVBUF_LOCK, SOCK_RCVBUF_LOCK },
		{ SO_BUF_LOCK, SOCK_SNDBUF_LOCK | SOCK_RCVBUF_LOCK, SOCK_SNDBUF_LOCK | SOCK_RCVBUF_LOCK },
		{ SO_SNDBUF, BUFSIZE, SOCK_SNDBUF_LOCK },
		{ SO_RCVBUF, BUFSIZE, SOCK_RCVBUF_LOCK } };

#define NSOCK ARRAY_SIZE(sk_opts)

char *type_to_str(int type)
{
	switch (type) {
	case SO_BUF_LOCK:
		return "SO_BUF_LOCK";
	case SO_SNDBUFFORCE:
		return "SO_SNDBUFFORCE";
	case SO_RCVBUFFORCE:
		return "SO_RCVBUFFORCE";
	}
	return NULL;
}

int main(int argc, char **argv)
{
	int sock[NSOCK];
	int ret, i;
	int exit_code = 1;

	test_init(argc, argv);

	for (i = 0; i < NSOCK; i++)
		sock[i] = -1;

	for (i = 0; i < NSOCK; i++) {
		uint32_t tmp;
		socklen_t len;

		sock[i] = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (sock[i] < 0) {
			pr_perror("can't create socket %d", i);
			goto err;
		}

		ret = setsockopt(sock[i], SOL_SOCKET, sk_opts[i].type, &sk_opts[i].val, sizeof(sk_opts[i].val));
		if (ret < 0) {
			pr_perror("can't set %s (%u) on socket %d", type_to_str(sk_opts[i].type), sk_opts[i].val, i);
			goto err;
		}

		len = sizeof(tmp);
		ret = getsockopt(sock[i], SOL_SOCKET, SO_BUF_LOCK, &tmp, &len);
		if (ret < 0) {
			pr_perror("can't get SO_BUF_LOCK from socket %d", i);
			goto err;
		}

		if (tmp != sk_opts[i].lock) {
			fail("SO_BUF_LOCK mismatch %u != %u", tmp, sk_opts[i].lock);
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

		if (tmp != sk_opts[i].lock) {
			fail("SO_BUF_LOCK mismatch %u != %u", tmp, sk_opts[i].lock);
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
