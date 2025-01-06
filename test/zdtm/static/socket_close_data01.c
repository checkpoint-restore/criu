#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/un.h>

#include "zdtmtst.h"

const char *test_doc = "Check data of bound socket and possibility to connect";
const char *test_author = "Kirill Tkhai <ktkhai@virtuozzo";

#define MSG "hello"
char *filename;
TEST_OPTION(filename, string, "file name", 1);

static int client(const char *iter)
{
	struct sockaddr_un addr;
	int sk;

	sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0) {
		pr_perror("open client %s", iter);
		return 1;
	}

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, filename);

	if (connect(sk, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0) {
		pr_perror("connect failed %s", iter);
		return 1;
	}

	if (send(sk, MSG, sizeof(MSG), 0) != sizeof(MSG)) {
		pr_perror("send failed %s", iter);
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct sockaddr_un addr;
	int srv, status, ret;
	char buf[1024];

	test_init(argc, argv);

	srv = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (srv < 0) {
		pr_perror("open srv");
		exit(1);
	}

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, filename);

	if (bind(srv, (struct sockaddr *)&addr, sizeof(struct sockaddr_un))) {
		pr_perror("bind srv");
		exit(1);
	}

	if (fork() == 0) {
		close(srv);
		client("(iter1)");
		exit(0);
	}
	ret = 1;
	if (wait(&status) == -1) {
		fail("wait failed");
		goto unlink;
	}
	if (status) {
		pr_err("A child exited with 0x%x\n", status);
		goto unlink;
	}

	test_daemon();
	test_waitsig();

	/* Test1: check we can read client message: */
	ret = read(srv, buf, sizeof(MSG));
	buf[ret > 0 ? ret : 0] = 0;
	if (ret != sizeof(MSG)) {
		fail("%d: %s", ret, buf);
		ret = 1;
		goto unlink;
	}

	/* Test2: check it's still possible to connect to the bound socket */
	if (fork() == 0) {
		exit(client("(iter2)"));
	}

	if (wait(&status) < 0) {
		fail("wait failed");
		goto unlink;
	}

	if (WEXITSTATUS(status) != 0) {
		fail("connect failed");
		goto unlink;
	}

	ret = 0;
	pass();
unlink:
	unlink(filename);
	return ret;
}
