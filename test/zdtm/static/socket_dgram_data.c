#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that data in dgram socket are restored correctly";
const char *test_author	= "Andrew Vagin <avagin@openvz.org";

#define SK_SRV "\0socket_dgram_srv"

#define MSG "hello"
int main(int argc, char **argv)
{
	struct sockaddr_un addr;
	unsigned int addrlen;
	int srv, clnt1, clnt2, ret;
	char buf[1024];

	test_init(argc, argv);

	srv = socket(PF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (srv < 0) {
		pr_perror("socket");
		return 1;
	}
	clnt1 = socket(PF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (clnt1 < 0) {
		pr_perror("socket");
		return 1;
	}
	clnt2 = socket(PF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (clnt2 < 0) {
		pr_perror("socket");
		return 1;
	}

	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, SK_SRV, sizeof(SK_SRV));
	addrlen = sizeof(addr.sun_family) + sizeof(SK_SRV);

	if (bind(srv, (struct sockaddr *) &addr, addrlen)) {
		fail("bind\n");
		exit(1);
	}
	if (connect(clnt1, (struct sockaddr *) &addr, addrlen)) {
		fail("connect\n");
		exit(1);
	}
	if (connect(clnt2, (struct sockaddr *) &addr, addrlen)) {
		fail("connect\n");
		exit(1);
	}

	if (write(clnt1, MSG, sizeof(MSG)) != sizeof(MSG)) {
		pr_perror("write");
		return 1;
	}

	test_daemon();
	test_waitsig();

	ret = read(srv, buf, sizeof(buf));
	buf[ret > 0 ? ret : 0] = 0;
	if (ret != sizeof(MSG)) {
		fail("%d: %s", ret, buf);
		return 1;
	}

	ret = read(srv, buf, sizeof(buf));
	if (ret != -1 || errno != EAGAIN) {
		fail("unexpected data: %d", ret);
		return 1;
	}

	pass();
	return 0;
}
