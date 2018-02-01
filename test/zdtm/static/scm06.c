#include <sys/resource.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc	= "Check a send of looped unix sockets";
const char *test_author	= "Kirill Tkhai <ktkhai@virtuozzo.com>";

static int send_fd(int via, int fd)
{
	struct msghdr h = {};
	struct cmsghdr *ch;
	struct iovec iov;
	char buf[CMSG_SPACE(sizeof(int))];
	char c = '\0';
	int *fdp;

	memset(buf, 0, sizeof(buf));
	h.msg_control = buf;
	h.msg_controllen = sizeof(buf);
	ch = CMSG_FIRSTHDR(&h);
	ch->cmsg_level = SOL_SOCKET;
	ch->cmsg_type = SCM_RIGHTS;
	ch->cmsg_len = CMSG_LEN(sizeof(int));
	fdp = (int *)CMSG_DATA(ch);
	fdp[0] = fd;

	h.msg_iov = &iov;
	h.msg_iovlen = 1;
	iov.iov_base = &c;
	iov.iov_len = sizeof(c);

	if (sendmsg(via, &h, 0) <= 0)
		return -1;

	return 0;
}

static int recv_fd(int via, int *fd)
{
	struct msghdr h = {};
	struct cmsghdr *ch;
	struct iovec iov;
	char buf[CMSG_SPACE(sizeof(int))];
	char c;
	int *fdp;

	h.msg_control = buf;
	h.msg_controllen = sizeof(buf);
	h.msg_iov = &iov;
	h.msg_iovlen = 1;
	iov.iov_base = &c;
	iov.iov_len = sizeof(c);

	if (recvmsg(via, &h, 0) <= 0)
		return -1;

	if (h.msg_flags & MSG_CTRUNC) {
		test_msg("CTR\n");
		return -2;
	}

	/* No 2 SCM-s here, kernel merges them upon send */
	ch = CMSG_FIRSTHDR(&h);
	if (h.msg_flags & MSG_TRUNC)
		return -2;
	if (ch == NULL)
		return -3;
	if (ch->cmsg_type != SCM_RIGHTS)
		return -4;

	fdp = (int *)CMSG_DATA(ch);
	*fd = fdp[0];
	return 0;
}

int main(int argc, char **argv)
{
	int ska[2], skc, i, j, ret;
	struct sockaddr_un addr;
	socklen_t len;

	test_init(argc, argv);

	if (socketpair(PF_UNIX, SOCK_DGRAM, 0, ska) < 0) {
		fail("Can't make unix pair");
		exit(1);
	}

	addr.sun_family = AF_UNIX;
	for (i = 0; i < 2; i++) {
		addr.sun_path[0] = '\0';
		addr.sun_path[1] = i;
		if (bind(ska[i], (struct sockaddr *)&addr,
			 sizeof(addr.sun_family) + 2)) {
			fail("Can't bind");
			exit(1);
		}
	}

	/* Make the vinaigrette */
	for (i = 0; i < 2; i++) {
		for (j = 0; j < 2; j++) {
			if (send_fd(ska[i], ska[j]) < 0) {
				fail("Can't send sk");
				exit(1);
			}
		}
	}

	test_daemon();
	test_waitsig();

	ret = -1;
	skc = ska[0];
	for (i = 0; i < 3; i++) {
		if (recv_fd(skc, &skc) < 0) {
			fail("Can't recv");
			goto out;
		}

		len = sizeof(addr.sun_family) + 2;

		if (getsockname(skc, (struct sockaddr *)&addr, &len)) {
			fail("Can't getsockname()");
			goto out;
		}

		if (addr.sun_path[1] != (i % 2)) {
			fail("Wrong socket or path");
			goto out;
		}
	}

	pass();
	ret = 0;
out:
	return ret;
}
