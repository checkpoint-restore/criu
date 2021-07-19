#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "zdtmtst.h"

const char *test_doc = "Check one end of socketpair with data";
const char *test_author = "Andrew Vagin <avagin@openvz.org";

#define MSG "hello"
int main(int argc, char **argv)
{
	int sks[2], ret;
	char buf[1024];

	test_init(argc, argv);

	if (socketpair(PF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, sks) < 0) {
		pr_perror("socketpair");
		return 1;
	}

	if (write(sks[1], MSG, sizeof(MSG)) != sizeof(MSG)) {
		pr_perror("write");
		return 1;
	}
	close(sks[1]);

	test_daemon();
	test_waitsig();

	ret = read(sks[0], buf, sizeof(MSG));
	buf[ret > 0 ? ret : 0] = 0;
	if (ret != sizeof(MSG)) {
		fail("%d: %s", ret, buf);
		return 1;
	}

	pass();
	return 0;
}
