#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check IP_RECVTTL ancillary data after restore";
const char *test_author = "B Srinivas Reddy <sriniv4sreddy@gmail.com>";

#ifdef ZDTM_VAL_ZERO
#define RECVTTL 0
#else
#define RECVTTL 1
#endif

static int check_ttl(int sk, unsigned short port)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = port,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	union {
		struct cmsghdr align;
		char data[CMSG_SPACE(sizeof(int))];
	} control;
	char byte = 0x5a;
	struct iovec iov = { .iov_base = &byte, .iov_len = sizeof(byte) };
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control.data,
		.msg_controllen = sizeof(control.data),
	};
	struct cmsghdr *cmsg;
	struct pollfd pfd = { .fd = sk, .events = POLLIN };
	int sender, ttl = 37, found = 0, ret = -1, ready;

	sender = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sender < 0) {
		pr_perror("socket");
		return -1;
	}
	if (setsockopt(sender, SOL_IP, IP_TTL, &ttl, sizeof(ttl))) {
		pr_perror("setsockopt IP_TTL");
		goto out;
	}
	if (sendto(sender, &byte, sizeof(byte), 0, (struct sockaddr *)&addr, sizeof(addr)) != sizeof(byte)) {
		pr_perror("sendto");
		goto out;
	}
	do {
		ready = poll(&pfd, 1, 1000);
	} while (ready < 0 && errno == EINTR);
	if (ready < 0) {
		pr_perror("poll");
		goto out;
	}
	if (!ready) {
		fail("Timed out waiting for datagram");
		goto out;
	}
	if (recvmsg(sk, &msg, MSG_DONTWAIT) != sizeof(byte)) {
		pr_perror("recvmsg");
		goto out;
	}
	if (byte != 0x5a || msg.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) {
		fail("Unexpected datagram");
		goto out;
	}
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != SOL_IP || cmsg->cmsg_type != IP_TTL)
			continue;
		if (cmsg->cmsg_len != CMSG_LEN(sizeof(ttl))) {
			fail("Unexpected IP_TTL length");
			goto out;
		}
		memcpy(&ttl, CMSG_DATA(cmsg), sizeof(ttl));
		if (ttl != 37) {
			fail("Unexpected TTL %d", ttl);
			goto out;
		}
		found++;
	}
	if (found != RECVTTL) {
		fail("Expected %d IP_TTL messages, got %d", RECVTTL, found);
		goto out;
	}
	ret = 0;
out:
	close(sender);
	return ret;
}

int main(int argc, char **argv)
{
	int sk[2] = { -1, -1 }, family[] = { AF_INET, AF_INET6 };
	unsigned short port[2];
	int i, val, ret = 1;

	test_init(argc, argv);
	for (i = 0; i < 2; i++) {
		struct sockaddr_storage addr = {};
		socklen_t len;

		sk[i] = socket(family[i], SOCK_DGRAM, IPPROTO_UDP);
		if (sk[i] < 0) {
			pr_perror("socket");
			goto out;
		}
		if (family[i] == AF_INET6) {
			val = 0;
			if (setsockopt(sk[i], SOL_IPV6, IPV6_V6ONLY, &val, sizeof(val))) {
				pr_perror("setsockopt IPV6_V6ONLY");
				goto out;
			}
			((struct sockaddr_in6 *)&addr)->sin6_family = AF_INET6;
			len = sizeof(struct sockaddr_in6);
		} else {
			((struct sockaddr_in *)&addr)->sin_family = AF_INET;
			((struct sockaddr_in *)&addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			len = sizeof(struct sockaddr_in);
		}
		if (bind(sk[i], (struct sockaddr *)&addr, len) ||
		    getsockname(sk[i], (struct sockaddr *)&addr, &len)) {
			pr_perror("bind/getsockname");
			goto out;
		}
		port[i] = family[i] == AF_INET ? ((struct sockaddr_in *)&addr)->sin_port :
						 ((struct sockaddr_in6 *)&addr)->sin6_port;
		val = RECVTTL;
		if (setsockopt(sk[i], SOL_IP, IP_RECVTTL, &val, sizeof(val))) {
			pr_perror("setsockopt IP_RECVTTL");
			goto out;
		}
		if (check_ttl(sk[i], port[i]))
			goto out;
	}

	test_daemon();
	test_waitsig();

	for (i = 0; i < 2; i++)
		if (check_ttl(sk[i], port[i]))
			goto out;
	pass();
	ret = 0;
out:
	for (i = 0; i < 2; i++)
		if (sk[i] >= 0)
			close(sk[i]);
	return ret;
}
