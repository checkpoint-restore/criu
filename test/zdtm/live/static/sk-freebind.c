#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>  /* for sockaddr_in and inet_ntoa() */

#include "zdtmtst.h"

const char *test_doc	= "Check that IP_FREEBIND is restored";
const char *test_author	= "Andrew Vagin <avagin@virtuozzo.com>";

union sockaddr_inet {
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
};

int main(int argc, char **argv)
{
	union sockaddr_inet addr;
	socklen_t len;
	int val, sock;

	test_init(argc, argv);

	addr.v6.sin6_family = AF_INET6;
	inet_pton(AF_INET6, "2001:db8::ff00:42:8329", &(addr.v6.sin6_addr));
	addr.v6.sin6_port = htons(56789);

	sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == -1) {
		pr_perror("socket() failed");
		return -1;
	}
	val = 1;
	if (setsockopt(sock, SOL_IP, IP_FREEBIND, &val, sizeof(int)) == -1 ) {
		pr_perror("setsockopt() error");
		return -1;
	}
	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr))) {
		pr_perror("bind()");
		return -1;
	}
#ifdef ZDTM_FREEBIND_FALSE
	val = 0;
	if (setsockopt(sock, SOL_IP, IP_FREEBIND, &val, sizeof(int)) == -1 ) {
		pr_perror("setsockopt() error");
		return -1;
	}
#endif

	test_daemon();
	test_waitsig();

	len = sizeof(int);
	if (getsockopt(sock, SOL_IP, IP_FREEBIND, &val, &len) == -1 ) {
		pr_perror("setsockopt() error");
		return -1;
	}

#ifdef ZDTM_FREEBIND_FALSE
	if (val) {
#else
	if (val == 0) {
#endif
		fail("Unexpected value: %d", val);
		return -1;
	}

	pass();

	return 0;
}
