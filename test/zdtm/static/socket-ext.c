
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

	char dir[] = "/tmp/zdtm.unix.sock.XXXXXX";
	char *path;
	pid_t pid;
	int ret, sk;

	if (mkdtemp(dir) < 0) {
		pr_perror("mkdtemp(%s) failed", dir);
		return 1;
	}
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path),
			"%s/%s", dir, "sock");
	path = addr.sun_path;
	addrlen = sizeof(addr.sun_family) + strlen(path);

	task_waiter_init(&lock);

	pid = fork();
	if (pid < 0) {
		pr_perror("fork() failed");
		return 1;
	} else if (pid == 0) {
		char c;
		test_ext_init(argc, argv);

		sk = socket(AF_UNIX, SOCK_DGRAM, 0);
		if (sk < 0) {
			pr_perror("Can't create socket");
			return 1;
		}
		ret = bind(sk, (struct sockaddr *) &addr, addrlen);
		if (ret < 0) {
			pr_perror("Can't bind socket to %s", path);
			return 1;
		}
		chmod(dir, 0777);
		chmod(path, 0777);
		test_msg("The external socket %s\n", path);
		task_waiter_complete(&lock, 1);
		task_waiter_fini(&lock);

		recv(sk, &c, sizeof(c), 0);

		return 0;
	}

	task_waiter_wait4(&lock, 1);
	task_waiter_fini(&lock);

	test_init(argc, argv);

	sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0) {
		pr_perror("Can't create socket");
		return 1;
	}

	ret = connect(sk, (struct sockaddr *) &addr, addrlen);
	if (ret < 0) {
		pr_perror("Can't connect socket");
		return 1;
	}


	test_daemon();
	test_waitsig();

	unlink(path);
	unlink(dir);

	ret = send(sk, "H", 1, 0);
	if (ret != 1) {
		pr_perror("Can't send a symbol");
		fail();
		return 1;
	}

	pass();
	return 0;
}
