
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

/* FIXME Need gram sockets tests */

const char *test_doc	= "Test unix stream sockets\n";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org";

#define SK_DATA "packet"

int main(int argc, char *argv[])
{
	int ssk_icon[2];
	int ssk_pair[2];
	struct sockaddr_un addr;
	unsigned int addrlen;

	char path[PATH_MAX] = { };
	char buf[64];
	char *cwd;

	int ret;

	test_init(argc, argv);

	cwd = get_current_dir_name();
	if (!cwd) {
		fail("getcwd\n");
		exit(1);
	}

	strncat(path, cwd, sizeof(path));
	strncat(path, "/test-socket", sizeof(path));
	unlink(path);
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path));
	addrlen = sizeof(addr.sun_family) + strlen(path);

	ssk_icon[0] = socket(AF_UNIX, SOCK_STREAM, 0);
	ssk_icon[1] = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ssk_icon[0] < 0 || ssk_icon[1] < 0) {
		fail("socket\n");
		exit(1);
	}

	ret = bind(ssk_icon[0], &addr, addrlen);
	if (ret) {
		fail("bind\n");
		exit(1);
	}

	ret = listen(ssk_icon[0], 16);
	if (ret) {
		fail("bind\n");
		exit(1);
	}

	ret = connect(ssk_icon[1], &addr, addrlen);
	if (ret) {
		fail("connect\n");
		exit(1);
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, ssk_pair) == -1) {
		fail("socketpair\n");
		exit(1);
	}

	write(ssk_pair[0], SK_DATA, sizeof(SK_DATA));
	read(ssk_pair[1], &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("stream            : '%s'\n", buf);

	test_daemon();
	test_waitsig();

	write(ssk_pair[0], SK_DATA, sizeof(SK_DATA));
	read(ssk_pair[1], &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("stream            : '%s'\n", buf);

	ret = accept(ssk_icon[0], NULL, NULL);
	if (ret < 0) {
		fail("accept\n");
		exit(1);
	} else
		ssk_icon[0] = ret;

	write(ssk_icon[1], SK_DATA, sizeof(SK_DATA));
	read(ssk_icon[0], &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("stream            : '%s'\n", buf);

	pass();
	return 0;
}
