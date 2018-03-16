#include <sched.h>
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

const char *test_doc	= "Test that unix sockets are restored in proper mount namespaces\n";
const char *test_author	= "Andrei Vagin <avagin@openvz.org>";

char *dirname;
TEST_OPTION(dirname, string, "socket file name", 1);

#define TEST_MODE 0640

int main(int argc, char *argv[])
{
	struct sockaddr_un addr;
	unsigned int addrlen;
	int sk, csk;
	pid_t pid;
	char path[PATH_MAX];
	char sbuf[256], rbuf[256];
	char *cwd;
	int ret, status, i;
	task_waiter_t t;

	test_init(argc, argv);

	task_waiter_init(&t);
	cwd = get_current_dir_name();
	if (!cwd) {
		fail("getcwd\n");
		exit(1);
	}

	mkdir(dirname, 0777);

	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		return 1;
	}

	if (pid == 0) {
		unshare(CLONE_NEWNS);
		if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL)) {
			pr_perror("mount");
			return 1;
		}
		if (mount("test", dirname, "tmpfs", 0, NULL)) {
			pr_perror("mount");
			return 1;
		}
	}

	addrlen = snprintf(path, sizeof(path), "%s/%s/%s", cwd, dirname, "test.socket");
	unlink(path);

	addr.sun_family = AF_UNIX;
	if (addrlen > sizeof(addr.sun_path))
		return 1;
	memcpy(addr.sun_path, path, addrlen);
	addrlen += sizeof(addr.sun_family);

	sk = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (sk < 0) {
		pr_perror("socket\n");
		exit(1);
	}
	csk = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (csk < 0) {
		pr_perror("socket\n");
		exit(1);
	}

	ret = bind(sk, (struct sockaddr *) &addr, addrlen);
	if (ret) {
		fail("bind\n");
		exit(1);
	}

	if (connect(csk, (struct sockaddr *) &addr, addrlen)) {
		fail("connect\n");
		exit(1);
	}

	if (pid) {
		task_waiter_wait4(&t, pid);
		test_daemon();
	} else {
		task_waiter_complete(&t, getpid());
	}

	test_waitsig();

	if (pid)
		kill(pid, SIGTERM);

	for (i = 0; i < 2; i++) {
		int len;

		memset(sbuf, 0, sizeof(sbuf));
		len = ssprintf(sbuf, "%d-%d test test test", getpid(), i);
		if (write(csk, sbuf, len) != len) {
			pr_perror("write");
			return 1;
		}
		memset(rbuf, 0, sizeof(rbuf));
		if (read(sk, &rbuf, sizeof(rbuf)) != len) {
			pr_perror("read");
			return 1;
		}

		if (strncmp(rbuf, sbuf, len)) {
			fail("data corrupted\n");
			exit(1);
		}

		close(csk);
		csk = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
		if (csk < 0) {
			pr_perror("socket\n");
			exit(1);
		}
		if (connect(csk, (struct sockaddr *) &addr, addrlen)) {
			pr_perror("connect");
			exit(1);
		}
	}
	close(sk);
	close(csk);
	unlink(path);

	if (pid) {
		if (waitpid(pid, &status, 0) != pid) {
			pr_perror("waitpid");
			return 1;
		}

		if (status) {
			fail("A child process returned %d", status);
			return 1;
		}
	}

	pass();
	return 0;
}
