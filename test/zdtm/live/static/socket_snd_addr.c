#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that sender addresses are restored";
const char *test_author	= "Andrew Vagin <avagin@openvz.org";

#define SK_SRV "\0socket_snd_srv"
#define SK_NAME "\0A-socket_snd_clnt"

char sk_names[2][128] = {
		SK_NAME,
		SK_NAME,
	};

#define MSG "hello"
int main(int argc, char **argv)
{
	struct sockaddr_un addr;
	unsigned int addrlen;
	int srv, clnt = -1, ret, i;
	char buf[1024];
	struct iovec iov = {
			.iov_base = &buf,
			.iov_len = sizeof(buf),
		};
	struct msghdr hdr = {
			.msg_name = &addr,
			.msg_namelen = sizeof(addr),
			.msg_iov = &iov,
			.msg_iovlen = 1,
		};

	test_init(argc, argv);

	srv = socket(PF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);

	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, SK_SRV, sizeof(SK_SRV));
	addrlen = sizeof(addr.sun_family) + sizeof(SK_SRV);

	if (bind(srv, &addr, addrlen)) {
		fail("bind\n");
		exit(1);
	}

	for (i = 0; i < 2; i++) {
		close(clnt);
		clnt = socket(PF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);

		sk_names[i][1] += i;
		addr.sun_family = AF_UNIX;
		memcpy(addr.sun_path, sk_names[i], sizeof(SK_NAME));
		addrlen = sizeof(addr.sun_family) + sizeof(SK_NAME);

		if (bind(clnt, &addr, addrlen)) {
			fail("bind\n");
			exit(1);
		}

		memcpy(addr.sun_path, SK_SRV, sizeof(SK_SRV));
		addrlen = sizeof(addr.sun_family) + sizeof(SK_SRV);
		if (connect(clnt, &addr, addrlen)) {
			fail("connect\n");
			exit(1);
		}

		if (send(clnt, MSG, sizeof(MSG), 0) != sizeof(MSG)) {
			err("write");
			return 1;
		}
	}

	test_daemon();
	test_waitsig();

	for (i = 0; i < 2; i++) {
		memset(addr.sun_path, 0, sizeof(addr.sun_path));
		ret = recvmsg(srv, &hdr, MSG_DONTWAIT);
		buf[ret > 0 ? ret : 0] = 0;
		if (ret != sizeof(MSG)) {
			fail("%d: %s", ret, buf);
			return 1;
		}
		if (hdr.msg_namelen > sizeof(addr.sun_family) + 1)
			err("%d, %s", hdr.msg_namelen, addr.sun_path + 1);
		if (memcmp(addr.sun_path, sk_names[i], sizeof(SK_NAME))) {
			fail("A sender address is mismatch");
			return 1;
		}
	}

	pass();
	return 0;
}
