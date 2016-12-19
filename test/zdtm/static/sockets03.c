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
#include <sys/mount.h>
#include <limits.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc	= "Test unix stream sockets with mismatch in shutdown state\n";
const char *test_author	= "Andrey Ryabinin <aryabinin@virtuozzo.com>";

#define SK_DATA "packet"

char *filename;
TEST_OPTION(filename, string, "socket file name", 1);

int main(int argc, char *argv[])
{
	int sk[3];
	struct sockaddr_un addr;
	unsigned int addrlen;
	char path[PATH_MAX];
	char buf[64];
	char *cwd;
	int ret;

	test_init(argc, argv);
    
	signal(SIGPIPE, SIG_IGN);

	cwd = get_current_dir_name();
	if (!cwd) {
		fail("getcwd\n");
		exit(1);
	}

	snprintf(path, sizeof(path), "%s/%s", cwd, filename);
	unlink(path);

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path));
	addrlen = sizeof(addr.sun_family) + strlen(path);

	sk[0] = socket(AF_UNIX, SOCK_STREAM, 0);
	sk[1] = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sk[0] < 0 || sk[1] < 0) {
		fail("socket\n");
		exit(1);
	}

	ret = bind(sk[0], &addr, addrlen);
	if (ret) {
		fail("bind\n");
		exit(1);
	}

	ret = listen(sk[0], 16);
	if (ret) {
		fail("listen\n");
		exit(1);
	}

	ret = shutdown(sk[1], SHUT_RD);
	if (ret) {
		fail("shutdown\n");
		exit(1);
	}

	ret = connect(sk[1], &addr, addrlen);
	if (ret) {
		fail("connect\n");
		exit(1);
	}

	sk[2] = accept(sk[0], NULL, NULL);
	if (sk[2] < 0) {
		fail("accept");
		exit(1);
	}

	test_daemon();
	test_waitsig();

	if (write(sk[1], SK_DATA, sizeof(SK_DATA)) < 0) {
		fail("write\n");
		exit(1);
	}

	if (read(sk[2], &buf, sizeof(buf)) < 0) {
		fail("read\n");
		exit(1);
	}

	if (strncmp(buf, SK_DATA, sizeof(SK_DATA))) {
		fail("data corrupted\n");
		exit(1);
	}

	if (write(sk[2], SK_DATA, sizeof(SK_DATA)) >= 0) {
		fail("successful write to shutdown receiver\n");
		exit(1);
	}

	close(sk[0]);
	close(sk[1]);
	close(sk[2]);

	pass();
	return 0;
}
