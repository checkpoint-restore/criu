#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc	= "Test semi-closed unix stream connection\n";
const char *test_author	= "Pavel Emelyanov <xemul@parallels.com>\n";

int main(int argc, char *argv[])
{
	int ssk_pair[2], ret;
	char aux;

	test_init(argc, argv);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, ssk_pair) == -1) {
		fail("socketpair\n");
		exit(1);
	}

	close(ssk_pair[1]);

	test_daemon();
	test_waitsig();

	errno = 0;
	ret = read(ssk_pair[0], &aux, sizeof(aux));
	if (ret != 0 || errno != 0) {
		fail("Opened end in wrong state (%d/%d)", ret, errno);
		return 0;
	}

	errno = 0;
	ret = read(ssk_pair[1], &aux, sizeof(aux));
	if (ret != -1 || errno != EBADF) {
		fail("Closed end in wrong state (%d/%d)", ret, errno);
		return 0;
	}

	pass();
	return 0;
}
