#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "zdtmtst.h"

const char *test_doc = "Check that SCM_RIGHTS & SCM_CREDENTIALS are preserved";
const char *test_author = "Alexander Mikhalitsyn <alexander.mikhalitsyn@virtuozzo.com>";

static int send_fd(int via, int fd)
{
	struct msghdr h = {};
	struct cmsghdr *ch;
	struct iovec iov = {
		.iov_base = (char *)"FDSTORE=1",
		.iov_len = sizeof("FDSTORE=1"),
	};
	char buf[CMSG_SPACE(sizeof(int))];
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

	if (sendmsg(via, &h, 0) <= 0)
		return -1;

	return 0;
}

static int send_creds(int via)
{
	struct msghdr h = {};
	struct cmsghdr *ch;
	struct iovec iov = {
		.iov_base = (char *)"CREDS=1",
		.iov_len = sizeof("CREDS=1"),
	};
	char buf[CMSG_SPACE(sizeof(struct ucred))];
	struct ucred *ucred;

	h.msg_control = buf;
	h.msg_controllen = sizeof(buf);
	ch = CMSG_FIRSTHDR(&h);
	ch->cmsg_level = SOL_SOCKET;
	ch->cmsg_type = SCM_CREDENTIALS;
	ch->cmsg_len = CMSG_LEN(sizeof(struct ucred));
	ucred = (struct ucred *)CMSG_DATA(ch);
	ucred->pid = getpid();
	ucred->uid = getuid();
	ucred->gid = getgid();
	h.msg_iov = &iov;
	h.msg_iovlen = 1;

	if (sendmsg(via, &h, 0) <= 0)
		return -1;

	return 0;
}

static int recv_fd(int via)
{
	struct msghdr h = {};
	struct cmsghdr *ch;
	char iovbuf[128];
	struct iovec iov = {
		.iov_base = iovbuf,
		.iov_len = sizeof(iovbuf),
	};
	char buf[1024];
	int *fdp = NULL;

next_msg:
	h.msg_control = buf;
	h.msg_controllen = sizeof(buf);
	h.msg_iov = &iov;
	h.msg_iovlen = 1;

	if (recvmsg(via, &h, MSG_DONTWAIT) <= 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return -3;
		else
			return -1;
	}

	if (h.msg_flags & MSG_TRUNC)
		return -2;

	for (ch = CMSG_FIRSTHDR(&h); ch; ch = CMSG_NXTHDR(&h, ch)) {
		if (ch->cmsg_type != SCM_RIGHTS)
			continue;

		fdp = (int *)CMSG_DATA(ch);
	}

	if (!fdp)
		goto next_msg;

	return fdp ? *fdp : -4;
}

int main(int argc, char **argv)
{
	int sk[2] = { -1, -1 }, p[2] = { -1, -1 }, rfd, ret = 1;

#define MSG "HELLO"
	char buf[8]; /* bigger than the MSG to check boundaries */

	test_init(argc, argv);

	if (socketpair(PF_UNIX, SOCK_DGRAM, 0, sk) < 0) {
		pr_perror("Can't make unix pair");
		exit(1);
	}

	if (setsockopt(sk[0], SOL_SOCKET, SO_PASSCRED, &(int){ 1 }, sizeof(int)) < 0 ||
	    setsockopt(sk[1], SOL_SOCKET, SO_PASSCRED, &(int){ 1 }, sizeof(int)) < 0) {
		pr_perror("setsockopt SO_PASSCRED");
		close(sk[0]);
		close(sk[1]);
		exit(1);
	}

	if (send_creds(sk[0]) < 0) {
		pr_perror("Can't send creds");
		close(sk[0]);
		close(sk[1]);
		exit(1);
	}

	/*
	 * We want to send this socket through
	 * "sk" unix socket.
	 *
	 * Also, we will send ucreds through "sk"
	 * unix socket.
	 */
	if (socketpair(PF_UNIX, SOCK_STREAM, 0, p) < 0) {
		pr_perror("Can't make socketpair to send");
		close(sk[0]);
		close(sk[1]);
		exit(1);
	}

	if (send_fd(sk[0], p[1]) < 0) {
		pr_perror("Can't send descriptor");
		close(sk[0]);
		close(sk[1]);
		close(p[0]);
		close(p[1]);
		exit(1);
	}

	/* we sent this side of socketpair */
	close(p[1]);

	test_daemon();
	test_waitsig();

	rfd = recv_fd(sk[1]);
	if (rfd < 0) {
		fail("Can't recv sk back (%d)", rfd);
		goto out;
	}

	if (write(p[0], MSG, sizeof(MSG)) != sizeof(MSG)) {
		fail("Socket write-broken");
		goto out;
	}

	if (read(rfd, buf, sizeof(buf)) != sizeof(MSG)) {
		fail("Socket read-broken");
		goto out;
	}

	if (strcmp(buf, MSG)) {
		buf[sizeof(buf) - 1] = '\0';
		fail("Socket read-broken (%s)", buf);
		goto out;
	}

	pass();
	ret = 0;
out:
	if (p[0] > 0)
		close(p[0]);
	if (rfd > 0)
		close(rfd);
	if (sk[0] > 0)
		close(sk[0]);
	if (sk[1] > 0)
		close(sk[1]);
	return ret;
}
