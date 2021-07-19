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

const char *test_doc = "Test unix stream socketpair\n";
const char *test_author = "Cyrill Gorcunov <gorcunov@openvz.org";

#define SK_DATA "packet"

int main(int argc, char *argv[])
{
	int ssk_pair[2];
	char buf[64];

	test_init(argc, argv);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, ssk_pair) == -1) {
		fail("socketpair");
		exit(1);
	}

	memset(buf, 0, sizeof(buf));
	write(ssk_pair[0], SK_DATA, sizeof(SK_DATA));
	read(ssk_pair[1], &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA)) {
		fail("data corrupted");
		exit(1);
	}
	test_msg("stream            : '%s'\n", buf);

	test_daemon();
	test_waitsig();

	memset(buf, 0, sizeof(buf));
	write(ssk_pair[0], SK_DATA, sizeof(SK_DATA));
	read(ssk_pair[1], &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA)) {
		fail("data corrupted");
		exit(1);
	}
	test_msg("stream            : '%s'\n", buf);

	pass();
	return 0;
}
