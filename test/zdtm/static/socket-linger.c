#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "zdtmtst.h"

const char *test_doc	= "Check SO_LINGER socket option";
const char *test_author	= "Radostin Stoyanov <rstoyanov1@gmail.com>";

int main(int argc, char **argv)
{
	int sk;
	struct linger dump = {true, 30}, restore = {0, 0};
	socklen_t optlen = sizeof(restore);

	test_init(argc, argv);

	sk = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0) {
		pr_perror("Can't create socket");
		return 1;
	}

	if (setsockopt(sk, SOL_SOCKET, SO_LINGER, &dump, sizeof(dump)) < 0) {
		pr_perror("setsockopt SO_LINGER");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (getsockopt(sk, SOL_SOCKET, SO_LINGER, &restore, &optlen) < 0) {
		pr_perror("getsockopt SO_LINGER");
		return 1;
	}

	if (restore.l_onoff != dump.l_onoff) {
		fail("linger.l_onoff has incorrect value (%d != %d)",
			restore.l_onoff, dump.l_onoff);
		return 1;
	}

	if (restore.l_linger != dump.l_linger) {
		fail("linger.l_linger has incorrect value (%d != %d)",
			restore.l_linger, dump.l_linger);
		return 1;
	}

	pass();
	return 0;
}