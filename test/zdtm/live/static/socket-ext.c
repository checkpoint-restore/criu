
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

const char *test_doc	= "Test external sockets\n";
const char *test_author	= "Andrey Vagin <avagin@openvz.org";

#define SK_DATA "packet"

int main(int argc, char *argv[])
{
	struct sockaddr_un addr;
	unsigned int addrlen;
	task_waiter_t lock;

	char path[PATH_MAX] = "/tmp/zdtm.unix.sock.XXXXXX";
	pid_t pid;
	int ret, sk;

	mktemp(path);
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path));
	addrlen = sizeof(addr.sun_family) + strlen(path);

	task_waiter_init(&lock);

	pid = fork();
	if (pid < 0) {
		err("fork() failed");
		return 1;
	} else if (pid == 0) {
		char c;
		test_ext_init(argc, argv);

		sk = socket(AF_UNIX, SOCK_DGRAM, 0);
		if (sk < 0) {
			err("Can't create socket");
			return 1;
		}
		ret = bind(sk, &addr, addrlen);
		if (ret < 0) {
			err("Can't bind socket to %s", path);
			return 1;
		}
		test_msg("The external socket %s\n", path);
		task_waiter_complete(&lock, 1);
		task_waiter_fini(&lock);

		recv(sk, &c, sizeof(c), 0);

		return 0;
	}

	test_init(argc, argv);

	task_waiter_wait4(&lock, 1);
	task_waiter_fini(&lock);

	sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0) {
		err("Can't create socket");
		return 1;
	}

	ret = connect(sk, &addr, addrlen);
	if (ret < 0) {
		err("Can't connect socket");
		return 1;
	}


	test_daemon();
	test_waitsig();

	unlink(path);

	ret = send(sk, "H", 1, 0);
	if (ret != 1) {
		err("Can't send a symbol");
		fail();
		return 1;
	}

	pass();
	return 0;
}
