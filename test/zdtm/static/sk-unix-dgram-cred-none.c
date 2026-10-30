#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "zdtmtst.h"
#include "zdtm_pidfd.h"

const char *test_doc = "Check C/R of packets queued without credentials before SO_PASSCRED was set\n";
const char *test_author = "Ahmed Elaidy <elaidya225@gmail.com>";

/*
 * A packet queued while neither end may pass credentials carries no struct
 * pid. Turning SO_PASSCRED on later makes the receiver see pid 0 and the
 * overflow uid/gid for it, and SO_PASSPIDFD hands out no pidfd at all.
 * After restore the receiver must see exactly that, not the credentials of
 * whoever refilled the queue.
 *
 * Two pairs, for the two ways the queue is refilled: a socketpair, and a
 * sender connected to a bound receiver, whose options are restored before
 * its queue is.
 */

static const char hello[] = "hello";

struct pkt_creds {
	struct ucred uc;
	int has_creds;
	int has_pidfd;
};

static int recv_pkt(int sk, int flags, struct pkt_creds *pc)
{
	char buf[sizeof(hello) + 1];
	char cbuf[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int))];
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

	memset(pc, 0, sizeof(*pc));

	n = recvmsg(sk, &msg, flags | MSG_DONTWAIT);
	if (n < 0)
		return -errno;

	if (n != sizeof(hello) || memcmp(buf, hello, n)) {
		pr_err("Unexpected packet of %zd bytes\n", n);
		return -EBADMSG;
	}

	if (msg.msg_flags & MSG_CTRUNC) {
		pr_err("Control data truncated\n");
		return -EMSGSIZE;
	}

	for (ch = CMSG_FIRSTHDR(&msg); ch; ch = CMSG_NXTHDR(&msg, ch)) {
		if (ch->cmsg_level != SOL_SOCKET)
			continue;

		if (ch->cmsg_type == SCM_CREDENTIALS) {
			memcpy(&pc->uc, CMSG_DATA(ch), sizeof(pc->uc));
			pc->has_creds = 1;
		} else if (ch->cmsg_type == SCM_PIDFD) {
			int pidfd;

			memcpy(&pidfd, CMSG_DATA(ch), sizeof(pidfd));
			if (pidfd >= 0 && !(flags & MSG_PEEK))
				close(pidfd);
			pc->has_pidfd = 1;
		}
	}

	return 0;
}

static int check_credless(const char *name, const struct pkt_creds *pc)
{
	if (!pc->has_creds) {
		fail("%s: no SCM_CREDENTIALS", name);
		return -1;
	}

	if (pc->uc.pid != 0) {
		fail("%s: packet is credited to pid %d, not to pid 0", name, pc->uc.pid);
		return -1;
	}

	if (pc->has_pidfd) {
		fail("%s: packet came with SCM_PIDFD", name);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct pkt_creds before[2], after;
	int pair[2], srv, cli, rcv[2], i, ret, one = 1;
	int passpidfd = 1;
	socklen_t addrlen;
	const char *names[2] = { "socketpair", "bound" };

	test_init(argc, argv);

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) < 0) {
		pr_perror("socketpair");
		return 1;
	}

	/* Abstract, so nothing on disk has to be cleaned up. */
	snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1, "zdtm-cred-none-%d", getpid());
	addrlen = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(addr.sun_path + 1);

	srv = socket(AF_UNIX, SOCK_DGRAM, 0);
	cli = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (srv < 0 || cli < 0) {
		pr_perror("socket");
		return 1;
	}

	if (bind(srv, (struct sockaddr *)&addr, addrlen) < 0 ||
	    connect(cli, (struct sockaddr *)&addr, addrlen) < 0) {
		pr_perror("bind/connect");
		return 1;
	}

	/* Queue both packets while no end may pass credentials. */
	if (send(pair[0], hello, sizeof(hello), 0) != sizeof(hello) ||
	    send(cli, hello, sizeof(hello), 0) != sizeof(hello)) {
		pr_perror("send");
		return 1;
	}

	rcv[0] = pair[1];
	rcv[1] = srv;

	for (i = 0; i < 2; i++) {
		if (setsockopt(rcv[i], SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) < 0) {
			pr_perror("setsockopt SO_PASSCRED");
			return 1;
		}

		/* SO_PASSPIDFD is optional, the test covers SO_PASSCRED without it. */
		if (setsockopt(rcv[i], SOL_SOCKET, SO_PASSPIDFD, &one, sizeof(one)) < 0) {
			if (errno != ENOPROTOOPT) {
				pr_perror("setsockopt SO_PASSPIDFD");
				return 1;
			}
			passpidfd = 0;
		}
	}

	test_msg("SO_PASSPIDFD %s\n", passpidfd ? "set" : "not supported");

	for (i = 0; i < 2; i++) {
		ret = recv_pkt(rcv[i], MSG_PEEK, &before[i]);
		if (ret) {
			pr_err("%s: no packet before C/R: %s\n", names[i], strerror(-ret));
			return 1;
		}

		/* What the kernel shows for an skb with no struct pid. */
		if (check_credless(names[i], &before[i]))
			return 1;
	}

	test_daemon();
	test_waitsig();

	for (i = 0; i < 2; i++) {
		ret = recv_pkt(rcv[i], 0, &after);
		if (ret) {
			fail("%s: packet is gone after C/R: %s", names[i], strerror(-ret));
			return 1;
		}

		if (check_credless(names[i], &after))
			return 1;

		if (after.uc.uid != before[i].uc.uid || after.uc.gid != before[i].uc.gid) {
			fail("%s: uid/gid %u/%u became %u/%u", names[i], before[i].uc.uid, before[i].uc.gid,
			     after.uc.uid, after.uc.gid);
			return 1;
		}

		ret = recv_pkt(rcv[i], 0, &after);
		if (ret != -EAGAIN) {
			fail("%s: expected an empty queue after C/R, got %d", names[i], ret);
			return 1;
		}
	}

	pass();
	return 0;
}
