#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "zdtmtst.h"

const char *test_doc = "test checkpoint/restore of SO_KEEPALIVE\n";
const char *test_author = "Radostin Stoyanov <rstoyanov1@gmail.com>\n";

int main(int argc, char **argv)
{
	int sk;
	int alive = 1;
	int cnt = 5;
	int idle = 10;
	int intvl = 15;
	int optval;
	socklen_t optlen;

	test_init(argc, argv);

	sk = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0) {
		pr_perror("Can't create socket");
		return 1;
	}

	/* Set the option active */
	if (setsockopt(sk, SOL_SOCKET, SO_KEEPALIVE, &alive, sizeof(alive)) < 0) {
		pr_perror("setsockopt SO_KEEPALIVE");
		return 1;
	}

	if (setsockopt(sk, SOL_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt)) < 0) {
		pr_perror("setsockopt TCP_KEEPCNT");
		return 1;
	}

	if (setsockopt(sk, SOL_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)) < 0) {
		pr_perror("setsockopt TCP_KEEPIDLE");
		return 1;
	}

	optval = 5;
	optlen = sizeof(optval);
	if (setsockopt(sk, SOL_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl)) < 0) {
		pr_perror("setsockopt TCP_KEEPINTVL");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (getsockopt(sk, SOL_SOCKET, SO_KEEPALIVE, &optval, &optlen)) {
		pr_perror("getsockopt SO_KEEPALIVE");
		return 1;
	}

	if (optlen != sizeof(optval) || optval != alive) {
		fail("SO_KEEPALIVE not set");
		return 1;
	}

	if (getsockopt(sk, SOL_TCP, TCP_KEEPCNT, &optval, &optlen) < 0) {
		pr_perror("getsockopt TCP_KEEPCNT");
		return 1;
	}

	if (optval != cnt) {
		fail("TCP_KEEPCNT has incorrect value (%d != %d)", cnt, optval);
		return 1;
	}

	if (getsockopt(sk, SOL_TCP, TCP_KEEPIDLE, &optval, &optlen) < 0) {
		pr_perror("getsockopt TCP_KEEPIDLE");
		return 1;
	}

	if (optval != idle) {
		fail("TCP_KEEPIDLE has incorrect value (%d != %d)", idle, optval);
		return 1;
	}

	if (getsockopt(sk, SOL_TCP, TCP_KEEPINTVL, &optval, &optlen) < 0) {
		pr_perror("getsockopt TCP_KEEPINTVL");
		return 1;
	}

	if (optval != intvl) {
		fail("TCP_KEEPINTVL has incorrect value (%d != %d)", intvl, optval);
		return 1;
	}

	pass();
	return 0;
}