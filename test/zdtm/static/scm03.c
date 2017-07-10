#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that SCM_RIGHTS are preserved";
const char *test_author	= "Pavel Emelyanov <xemul@virtuozzo.com>";

static int send_fd(int via, int fd1, int fd2)
{
	struct msghdr h = {};
	struct cmsghdr *ch;
	struct iovec iov;
	char buf[CMSG_SPACE(2 * sizeof(int))], c = '\0';
	int *fdp;

	h.msg_control = buf;
	h.msg_controllen = sizeof(buf);
	ch = CMSG_FIRSTHDR(&h);
	ch->cmsg_level = SOL_SOCKET;
	ch->cmsg_type = SCM_RIGHTS;
	ch->cmsg_len = CMSG_LEN(2 * sizeof(int));
	fdp = (int *)CMSG_DATA(ch);
	fdp[0] = fd1;
	fdp[1] = fd2;
	h.msg_iov = &iov;
	h.msg_iovlen = 1;
	iov.iov_base = &c;
	iov.iov_len = sizeof(c);

	if (sendmsg(via, &h, 0) <= 0)
		return -1;

	return 0;
}

static int recv_fd(int via, int *fd1, int *fd2)
{
	struct msghdr h = {};
	struct cmsghdr *ch;
	struct iovec iov;
	char buf[CMSG_SPACE(2 * sizeof(int))], c;
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
	*fd1 = fdp[0];
	*fd2 = fdp[1];
	return 0;
}

int main(int argc, char **argv)
{
	int sk[2], p[2];
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

	if (send_fd(sk[0], p[0], p[1]) < 0) {
		pr_perror("Can't send descriptor");
		exit(1);
	}

	close(p[0]);
	close(p[1]);
	p[0] = p[1] = -1;

	test_daemon();
	test_waitsig();

	if (recv_fd(sk[1], &p[0], &p[1]) < 0) {
		fail("Can't recv pipes back");
		goto out;
	}

	if (write(p[1], MSG, sizeof(MSG)) != sizeof(MSG)) {
		fail("Pipe write-broken");
		goto out;
	}

	if (read(p[0], buf, sizeof(buf)) != sizeof(MSG)) {
		fail("Pipe read-broken");
		goto out;
	}

	if (strcmp(buf, MSG)) {
		buf[sizeof(buf) - 1] = '\0';
		fail("Pipe read-broken (%s)", buf);
		goto out;
	}

	pass();
out:
	return 0;
}
