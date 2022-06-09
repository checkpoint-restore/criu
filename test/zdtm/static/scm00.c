#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "zdtmtst.h"

const char *test_doc = "Check that SCM_RIGHTS are preserved";
const char *test_author = "Pavel Emelyanov <xemul@virtuozzo.com>";

static int send_fd(int via, int fd)
{
	struct msghdr h = {};
	struct cmsghdr *ch;
	struct iovec iov;
	char buf[CMSG_SPACE(sizeof(int))], c = '\0';
	int *fdp;

	h.msg_control = buf;
	h.msg_controllen = sizeof(buf);
	ch = CMSG_FIRSTHDR(&h);
	ch->cmsg_level = SOL_SOCKET;
	ch->cmsg_type = SCM_RIGHTS;
	ch->cmsg_len = CMSG_LEN(sizeof(int));
	fdp = (int *)CMSG_DATA(ch);
	*fdp = fd;
	h.msg_iov = &iov;
	h.msg_iovlen = 1;
	iov.iov_base = &c;
	iov.iov_len = sizeof(c);

	if (sendmsg(via, &h, 0) <= 0)
		return -1;

	return 0;
}

static int recv_fd(int via)
{
	struct msghdr h = {};
	struct cmsghdr *ch;
	struct iovec iov;
	char buf[CMSG_SPACE(sizeof(int))], c;
	int *fdp;

	h.msg_control = buf;
	h.msg_controllen = sizeof(buf);
	h.msg_iov = &iov;
	h.msg_iovlen = 1;
	iov.iov_base = &c;
	iov.iov_len = sizeof(c);

	if (recvmsg(via, &h, 0) <= 0)
		return -1;

	ch = CMSG_FIRSTHDR(&h);
	if (h.msg_flags & MSG_TRUNC)
		return -2;
	if (ch == NULL)
		return -3;
	if (ch->cmsg_type != SCM_RIGHTS)
		return -4;

	fdp = (int *)CMSG_DATA(ch);
	return *fdp;
}

int main(int argc, char **argv)
{
	int sk[2], p[2], rfd;
#define MSG "HELLO"
	char buf[8]; /* bigger than the MSG to check boundaries */

	test_init(argc, argv);

	if (socketpair(PF_UNIX, SOCK_DGRAM, 0, sk) < 0) {
		pr_perror("Can't make unix pair");
		exit(1);
	}

	if (pipe(p) < 0) {
		pr_perror("Can't make pipe");
		exit(1);
	}

	if (send_fd(sk[0], p[0]) < 0) {
		pr_perror("Can't send descriptor");
		exit(1);
	}

#ifndef KEEP_SENT_FD
	close(p[0]);
#ifdef SEND_BOTH
	if (send_fd(sk[0], p[1]) < 0) {
		pr_perror("Can't send 2nd descriptor");
		exit(1);
	}
	close(p[1]);
	p[0] = p[1] = -1;
#else
	/* Swap pipe ends to make scm recv put pipe into different place */
	dup2(p[1], p[0]);
	close(p[1]);
	p[1] = p[0];
	p[0] = -1;
#endif
#endif
#ifdef CLOSE_SENDER_FD
	close(sk[0]);
#endif

	test_daemon();
	test_waitsig();

	rfd = recv_fd(sk[1]);
	if (rfd < 0) {
		fail("Can't recv pipe back (%d)", p[0]);
		goto out;
	}

#ifdef SEND_BOTH
	test_msg("Recv 2nd end\n");
	p[1] = recv_fd(sk[1]);
	if (p[1] < 0) {
		fail("Can't recv 2nd pipe back (%d)", p[1]);
		goto out;
	}
#endif

#ifdef KEEP_SENT_FD
	if (rfd == p[0]) {
		fail("Original descriptor not kept");
		goto out;
	}
again:
#endif
	if (write(p[1], MSG, sizeof(MSG)) != sizeof(MSG)) {
		fail("Pipe write-broken");
		goto out;
	}

	if (read(rfd, buf, sizeof(buf)) != sizeof(MSG)) {
		fail("Pipe read-broken");
		goto out;
	}

	if (strcmp(buf, MSG)) {
		buf[sizeof(buf) - 1] = '\0';
		fail("Pipe read-broken (%s)", buf);
		goto out;
	}

#ifdef KEEP_SENT_FD
	if (rfd != p[0]) {
		test_msg("Check kept\n");
		rfd = p[0];
		goto again;
	}
#endif

	pass();
out:
	return 0;
}
