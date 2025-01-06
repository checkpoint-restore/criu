#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>

#include "zdtmtst.h"

const char *test_doc = "Check that SCM_RIGHTS are preserved";
const char *test_author = "Kirill Tkhai <ktkhai@virtuozzo.com>";

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
	struct epoll_event event = {
		.events = EPOLLIN,
	};
	int sk[2], ep, ret;

	test_init(argc, argv);

	if (socketpair(PF_UNIX, SOCK_DGRAM, 0, sk) < 0) {
		pr_perror("Can't make unix pair");
		exit(1);
	}

	ep = epoll_create(1);
	if (ep < 0) {
		perror("Can't create epoll");
		exit(1);
	}

	event.data.fd = sk[1];
	if (epoll_ctl(ep, EPOLL_CTL_ADD, sk[1], &event) < 0) {
		perror("Can't add fd");
		exit(1);
	}

	if (send_fd(sk[0], ep) < 0) {
		pr_perror("Can't send epoll");
		exit(1);
	}
	if (send_fd(sk[0], ep) < 0) {
		pr_perror("Can't send epoll");
		exit(1);
	}

	close(ep);
	memset(&event, 0, sizeof(event));

	test_daemon();
	test_waitsig();

	if (recv_fd(sk[1], &ep) < 0) {
		fail("Can't recv epoll back");
		ret = -1;
		goto out;
	}

	ret = epoll_wait(ep, &event, 1, 0);
	if (ret != 1) {
		fail("Can't get epoll event");
		ret = -1;
		goto out;
	}

	pass();
	ret = 0;
out:
	return ret;
}
