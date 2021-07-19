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

#define NOPTS 8

int main(int argc, char **argv)
{
	int sock, ret = 0, vname[NOPTS], val[NOPTS], rval, i;
	socklen_t len = sizeof(int);

	vname[0] = SO_PRIORITY;
	vname[1] = SO_RCVLOWAT;
	vname[2] = SO_MARK;
	vname[3] = SO_PASSCRED;
	vname[4] = SO_PASSSEC;
	vname[5] = SO_DONTROUTE;
	vname[6] = SO_NO_CHECK;
	vname[7] = SO_OOBINLINE;

	test_init(argc, argv);

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		pr_perror("can't create socket");
		return 1;
	}

	for (i = 0; i < NOPTS; i++) {
		ret = getsockopt(sock, SOL_SOCKET, vname[i], &val[i], &len);
		if (ret) {
			pr_perror("can't get option %d", i);
			return 1;
		}

		val[i]++;

		ret = setsockopt(sock, SOL_SOCKET, vname[i], &val[i], len);
		if (ret) {
			pr_perror("can't set option %d", i);
			return 1;
		}

		ret = getsockopt(sock, SOL_SOCKET, vname[i], &rval, &len);
		if (ret) {
			pr_perror("can't get option %d 2", i);
			return 1;
		}

		if (rval != val[i]) {
			if (rval + 1 == val[i]) {
				pr_perror("can't reset option %d want %d have %d", i, val[i], rval);
				return 1;
			}

			/* kernel tuned things up on set */
			val[i] = rval;
		}
	}

	test_daemon();
	test_waitsig();

	for (i = 0; i < NOPTS; i++) {
		ret = getsockopt(sock, SOL_SOCKET, vname[i], &rval, &len);
		if (ret) {
			pr_perror("can't get option %d again", i);
			return 1;
		}

		if (val[i] != rval) {
			fail("option %d changed", i);
			return 1;
		}
	}

	pass();
	close(sock);

	return 0;
}
