
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
#include <sys/mount.h>
#include <limits.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc	= "Test unix stream sockets with relative name\n";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org";

#define SK_DATA "packet"

char *filename;
TEST_OPTION(filename, string, "socket file name", 1);

#define TEST_MODE 0640

int main(int argc, char *argv[])
{
	struct sockaddr_un addr;
	unsigned int addrlen;
	int sock[2];

	char path[PATH_MAX];
	char buf[64];
	char *cwd;
	int ret;

	test_init(argc, argv);

	cwd = get_current_dir_name();
	if (!cwd) {
		fail("getcwd\n");
		exit(1);
	}

	snprintf(path, sizeof(path), "%s/%s", cwd, filename);
	unlink(path);

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, filename, sizeof(addr.sun_path));
	addrlen = sizeof(addr.sun_family) + strlen(filename);

	sock[0] = socket(AF_UNIX, SOCK_STREAM, 0);
	sock[1] = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock[0] < 0 || sock[1] < 0) {
		fail("socket\n");
		exit(1);
	}

	if (setsockopt(sock[0], SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0 ||
	    setsockopt(sock[1], SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0) {
		fail("setsockopt\n");
		exit(1);
	}

	ret = bind(sock[0], (struct sockaddr *) &addr, addrlen);
	if (ret) {
		fail("bind\n");
		exit(1);
	}

	ret = listen(sock[0], 16);
	if (ret) {
		fail("bind\n");
		exit(1);
	}

	test_daemon();
	test_waitsig();

	if (connect(sock[1], (struct sockaddr *) &addr, addrlen)) {
		fail("connect\n");
		exit(1);
	}

	ret = accept(sock[0], NULL, NULL);
	if (ret < 0) {
		fail("accept");
		exit(1);
	}

	memset(buf, 0, sizeof(buf));
	write(sock[1], SK_DATA, sizeof(SK_DATA));
	read(ret, &buf, sizeof(buf));

	if (strcmp(buf, SK_DATA)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("stream            : '%s'\n", buf);
	close(sock[0]);
	close(sock[1]);
	unlink(path);

	pass();
	return 0;
}
