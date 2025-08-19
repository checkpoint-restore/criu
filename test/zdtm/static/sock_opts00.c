#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "zdtmtst.h"

const char *test_doc = "Check various socket options to work";
const char *test_author = "Pavel Emelyanov <xemul@parallels.com>";

#define TEST_PORT 59687
#define TEST_ADDR INADDR_ANY

int main(int argc, char **argv)
{
	#define OPT(x) { x, #x }
	static const struct {
		int opt;
		const char *name;
	} vname[] = {
		OPT(SO_PRIORITY),
		OPT(SO_RCVLOWAT),
		OPT(SO_MARK),
		OPT(SO_PASSCRED),
		OPT(SO_PASSSEC),
		OPT(SO_DONTROUTE),
		OPT(SO_NO_CHECK),
		OPT(SO_OOBINLINE),
	};
	static const int NOPTS = sizeof(vname) / sizeof(*vname);
	#undef OPT

	int sock, usock, ret = 0, val[NOPTS], rval, i;
	socklen_t len = sizeof(int);
	int exit_code = 1;

	test_init(argc, argv);

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		pr_perror("can't create socket");
		return 1;
	}

	usock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (usock < 0) {
		pr_perror("can't create unix socket");
		close(sock);
		return 1;
	}

	for (i = 0; i < NOPTS; i++) {
		int sk = (vname[i].opt == SO_PASSCRED || vname[i].opt == SO_PASSSEC) ? usock : sock;

		ret = getsockopt(sk, SOL_SOCKET, vname[i].opt, &val[i], &len);
		if (ret) {
			pr_perror("can't get %s", vname[i].name);
			goto out;
		}

		val[i]++;

		ret = setsockopt(sk, SOL_SOCKET, vname[i].opt, &val[i], len);
		if (ret) {
			pr_perror("can't set %s = %d", vname[i].name, val[i]);
			goto out;
		}

		ret = getsockopt(sk, SOL_SOCKET, vname[i].opt, &rval, &len);
		if (ret) {
			pr_perror("can't re-get %s", vname[i].name);
			goto out;
		}

		if (rval != val[i]) {
			if (rval + 1 == val[i]) {
				pr_perror("failed to set %s: want %d have %d", vname[i].name, val[i], rval);
				goto out;
			}

			/* kernel tuned things up on set */
			val[i] = rval;
		}
	}

	test_daemon();
	test_waitsig();

	for (i = 0; i < NOPTS; i++) {
		int sk = (vname[i].opt == SO_PASSCRED || vname[i].opt == SO_PASSSEC) ? usock : sock;

		ret = getsockopt(sk, SOL_SOCKET, vname[i].opt, &rval, &len);
		if (ret) {
			pr_perror("can't verify %s", vname[i].name);
			goto out;
		}

		if (val[i] != rval) {
			errno = 0;
			fail("%s changed: %d -> %d", vname[i].name, val[i], rval);
			goto out;
		}
	}

	pass();
	exit_code = 0;
out:
	close(sock);
	close(usock);

	return exit_code;
}
