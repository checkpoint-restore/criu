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

const char *test_doc = "Test unix stream sockets with mismatch in shutdown state\n";
const char *test_author = "Andrey Ryabinin <aryabinin@virtuozzo.com>";

#define SK_DATA "packet"

char *filename;
TEST_OPTION(filename, string, "socket file name", 1);

#ifdef ZDTM_UNIX_SEQPACKET
#define SOCK_TYPE SOCK_SEQPACKET
#else
#define SOCK_TYPE SOCK_STREAM
#endif

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
		fail("getcwd");
		exit(1);
	}

	snprintf(path, sizeof(path), "%s/%s", cwd, filename);
	unlink(path);

	addr.sun_family = AF_UNIX;
	addrlen = strlen(path);
	if (addrlen >= sizeof(addr.sun_path))
		return 1;
	memcpy(addr.sun_path, path, addrlen);
	addrlen += sizeof(addr.sun_family);

	sk[0] = socket(AF_UNIX, SOCK_TYPE, 0);
	sk[1] = socket(AF_UNIX, SOCK_TYPE, 0);
	if (sk[0] < 0 || sk[1] < 0) {
		fail("socket");
		exit(1);
	}

	ret = bind(sk[0], (struct sockaddr *)&addr, addrlen);
	if (ret) {
		fail("bind");
		exit(1);
	}

	ret = listen(sk[0], 16);
	if (ret) {
		fail("listen");
		exit(1);
	}

	ret = shutdown(sk[1], SHUT_RD);
	if (ret) {
		fail("shutdown");
		exit(1);
	}

	ret = connect(sk[1], (struct sockaddr *)&addr, addrlen);
	if (ret) {
		fail("connect");
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
		fail("write");
		exit(1);
	}

	if (read(sk[2], &buf, sizeof(buf)) < 0) {
		fail("read");
		exit(1);
	}

	if (strncmp(buf, SK_DATA, sizeof(SK_DATA))) {
		fail("data corrupted");
		exit(1);
	}

	if (write(sk[2], SK_DATA, sizeof(SK_DATA)) >= 0) {
		fail("successful write to shutdown receiver");
		exit(1);
	}

	close(sk[0]);
	close(sk[1]);
	close(sk[2]);

	pass();
	return 0;
}
