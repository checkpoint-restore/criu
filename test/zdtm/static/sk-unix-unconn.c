#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "zdtmtst.h"

const char *test_doc = "Check unconnected unix sockets";
const char *test_author = "Vagin Andrew <avagin@parallels.com>";

#ifdef ZDTM_UNIX_SEQPACKET
#define SOCK_TYPE SOCK_SEQPACKET
#else
#define SOCK_TYPE SOCK_STREAM
#endif

int main(int argc, char **argv)
{
	int sk, skc;
	int ret, len;
	char path[PATH_MAX];
	struct sockaddr_un addr;
	socklen_t addrlen;

	test_init(argc, argv);

	sk = socket(AF_UNIX, SOCK_TYPE, 0);
	if (sk == -1) {
		pr_perror("socket");
		return 1;
	}

	skc = socket(AF_UNIX, SOCK_TYPE, 0);
	if (skc == -1) {
		pr_perror("socket");
		return 1;
	}

	len = snprintf(path, sizeof(path), "X/zdtm-%s-%d/X", argv[0], getpid());

	if (len >= sizeof(addr.sun_path)) {
		pr_err("%s\n", path);
		return 1;
	}
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, path, len);
	addrlen = sizeof(addr.sun_family) + len;
	addr.sun_path[0] = 0;
	addr.sun_path[len - 1] = 0;

	ret = bind(sk, (struct sockaddr *)&addr, addrlen);
	if (ret) {
		fail("bind");
		return 1;
	}

	test_daemon();

	test_waitsig();

	if (listen(sk, 1) == -1) {
		pr_perror("listen");
		return 1;
	}

	if (connect(skc, (struct sockaddr *)&addr, addrlen) == -1) {
		fail("Unable to connect");
		return 1;
	}

	pass();

	return 0;
}
