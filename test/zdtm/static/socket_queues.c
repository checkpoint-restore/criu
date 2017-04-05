
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

/* FIXME Need gram sockets tests */

const char *test_doc	= "Test unix sockets queues (2 messages in queue)\n";
const char *test_author	= "Stanislav Kinsbursky <skinsbursky@parallels.com>\n";

#define SK_DATA_S1 "packet stream left"
#define SK_DATA_S2 "packet stream right"
#define SK_DATA_D1 "packet dgram left"
#define SK_DATA_D2 "packet dgram right"

int main(int argc, char *argv[])
{
	int ssk_pair_d[2];
	int ssk_pair_s[2];
	char buf_left[64], buf_right[64];

	test_init(argc, argv);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, ssk_pair_s) == -1) {
		fail("socketpair\n");
		exit(1);
	}

	write(ssk_pair_s[0], SK_DATA_S1, sizeof(SK_DATA_S1));
	write(ssk_pair_s[0], SK_DATA_S2, sizeof(SK_DATA_S2));
	write(ssk_pair_s[1], SK_DATA_S2, sizeof(SK_DATA_S2));
	write(ssk_pair_s[1], SK_DATA_S1, sizeof(SK_DATA_S1));

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, ssk_pair_d) == -1) {
		fail("socketpair\n");
		exit(1);
	}

	write(ssk_pair_d[0], SK_DATA_D1, sizeof(SK_DATA_D1));
	write(ssk_pair_d[0], SK_DATA_D2, sizeof(SK_DATA_D2));
	write(ssk_pair_d[1], SK_DATA_D2, sizeof(SK_DATA_D2));
	write(ssk_pair_d[1], SK_DATA_D1, sizeof(SK_DATA_D1));

	test_daemon();
	test_waitsig();

	read(ssk_pair_s[1], buf_left, strlen(SK_DATA_S1) + 1);
	if (strcmp(buf_left, SK_DATA_S1)) {
		fail("SK_DATA_S2: '%s\n", SK_DATA_S1);
		exit(1);
	}
	read(ssk_pair_s[1], buf_right, strlen(SK_DATA_S2) + 1);
	if (strcmp(buf_right, SK_DATA_S2)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("stream1            : '%s' '%s'\n", buf_left, buf_right);

	read(ssk_pair_s[0], buf_left, strlen(SK_DATA_S2) + 1);
	if (strcmp(buf_left, SK_DATA_S2)) {
		fail("data corrupted\n");
		exit(1);
	}
	read(ssk_pair_s[0], buf_right, strlen(SK_DATA_S1) + 1);
	if (strcmp(buf_right, SK_DATA_S1)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("stream2            : '%s' '%s'\n", buf_left, buf_right);

	read(ssk_pair_d[1], buf_left, strlen(SK_DATA_D1) + 1);
	if (strcmp(buf_left, SK_DATA_D1)) {
		fail("data corrupted\n");
		exit(1);
	}
	read(ssk_pair_d[1], buf_right, strlen(SK_DATA_D2) + 1);
	if (strcmp(buf_right, SK_DATA_D2)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("dgram1            : '%s' '%s'\n", buf_left, buf_right);

	read(ssk_pair_d[0], buf_left, strlen(SK_DATA_D2) + 1);
	if (strcmp(buf_left, SK_DATA_D2)) {
		fail("data corrupted\n");
		exit(1);
	}
	read(ssk_pair_d[0], buf_right,strlen(SK_DATA_D1) + 1);
	if (strcmp(buf_right, SK_DATA_D1)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("dgram2            : '%s' '%s'\n", buf_left, buf_right);

	pass();
	return 0;
}
