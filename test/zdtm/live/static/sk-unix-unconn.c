#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "zdtmtst.h"

const char *test_doc	= "Check unconnected unix sockets";
const char *test_author	= "Vagin Andrew <avagin@parallels.com>";

int main(int argc, char ** argv)
{
	int sk, skc;
	int ret;
	char path[PATH_MAX];
	struct sockaddr_un addr;
	socklen_t addrlen;

	test_init(argc, argv);

	sk = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sk == -1) {
		err("socket\n");
		return 1;
	}

	skc = socket(AF_UNIX, SOCK_STREAM, 0);
	if (skc == -1) {
		err("socket\n");
		return 1;
	}

	snprintf(path, sizeof(path), "X/zdtm-%s-%d", argv[0], getpid());

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path));
	addrlen = sizeof(addr.sun_family) + strlen(path);
	addr.sun_path[0] = 0;

	ret = bind(sk, (struct sockaddr *) &addr, addrlen);
	if (ret) {
		fail("bind\n");
		return 1;
	}

	test_daemon();

	test_waitsig();

	if (listen(sk, 1) == -1) {
		err("listen");
		return 1;
	}

	if (connect(skc, (struct sockaddr *) &addr, addrlen) == -1) {
		fail("Unable to connect");
		return 1;
	}

	pass();

	return 0;
}
