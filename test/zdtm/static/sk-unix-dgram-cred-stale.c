#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include "zdtmtst.h"
#include "zdtm_pidfd.h"

const char *test_doc = "Check C/R of a packet from a dead sender on a socket with SO_PASSCRED only\n";
const char *test_author = "Ahmed Elaidy <elaidya225@gmail.com>";

/*
 * The receiver asks for SCM_CREDENTIALS and never for SCM_PIDFD, and its
 * queue holds a packet from a sender that has been reaped. Dump has to tell
 * such a sender from one that merely is not in the dumped tree all the same,
 * or the packet is dropped. After restore the packet has to be there, with
 * the sender's uid and gid, and still from a process that is dead: not from
 * us, who refill the queue on restore, and not from anything alive.
 */

/* What zdtm_queue_msg_from_dead_child() sends. */
static const char hello[] = "hello";

static int recv_creds(int sk, int flags, struct ucred *uc)
{
	char buf[sizeof(hello) + 1], cbuf[CMSG_SPACE(sizeof(struct ucred))];
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = sizeof(buf),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),
	};
	struct cmsghdr *ch;
	ssize_t n;

	n = recvmsg(sk, &msg, flags | MSG_DONTWAIT);
	if (n < 0)
		return -errno;

	if (n != sizeof(hello) || memcmp(buf, hello, n)) {
		pr_err("Unexpected packet of %zd bytes\n", n);
		return -EBADMSG;
	}

	for (ch = CMSG_FIRSTHDR(&msg); ch; ch = CMSG_NXTHDR(&msg, ch)) {
		if (ch->cmsg_level == SOL_SOCKET && ch->cmsg_type == SCM_CREDENTIALS) {
			memcpy(uc, CMSG_DATA(ch), sizeof(*uc));
			return 0;
		}
	}

	return -ENODATA;
}

int main(int argc, char **argv)
{
	struct ucred before, after;
	int sk[2], opt = 1, ret;
	pid_t sender;

	test_init(argc, argv);

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sk) < 0) {
		pr_perror("socketpair");
		return 1;
	}

	if (setsockopt(sk[1], SOL_SOCKET, SO_PASSCRED, &opt, sizeof(opt)) < 0) {
		pr_perror("setsockopt SO_PASSCRED");
		return 1;
	}

	sender = zdtm_queue_msg_from_dead_child(&sk[0], 1, 42, 0, NULL);
	if (sender < 0)
		return 1;

	ret = recv_creds(sk[1], MSG_PEEK, &before);
	if (ret) {
		fail("No packet with credentials before C/R: %s", strerror(-ret));
		return 1;
	}

	if (before.pid != sender) {
		fail("Packet from %d is credited to %d before C/R", sender, before.pid);
		return 1;
	}

	test_daemon();
	test_waitsig();

	ret = recv_creds(sk[1], 0, &after);
	if (ret) {
		fail("Packet from the dead sender is gone after C/R: %s", strerror(-ret));
		return 1;
	}

	if (after.uid != before.uid || after.gid != before.gid) {
		fail("Sender uid/gid %u/%u became %u/%u", before.uid, before.gid, after.uid, after.gid);
		return 1;
	}

	/*
	 * Restore refills the queue from this very process, so a packet sent
	 * without credentials of its own would come out credited to us.
	 */
	if (after.pid == getpid()) {
		fail("Packet from the dead sender is credited to us after C/R");
		return 1;
	}

	if (after.pid <= 0 || kill(after.pid, 0) == 0 || errno != ESRCH) {
		fail("Packet is credited to %d after C/R, not to a dead process", after.pid);
		return 1;
	}

	ret = recv_creds(sk[1], 0, &after);
	if (ret != -EAGAIN) {
		fail("Expected an empty queue after C/R, got %d", ret);
		return 1;
	}

	pass();
	return 0;
}
