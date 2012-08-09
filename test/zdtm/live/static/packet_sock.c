#include "zdtmtst.h"

const char *test_doc = "static test for packet sockets";
const char *test_author = "Pavel Emelyanov <xemul@parallels.com>";

/*
 * Description:
 *  Create and bind several packet sockets, check thet getname
 *  reports same result before and after c/r cycle. This is enough
 *  for _basic_ packet functionality only, but still.
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

static int test_sockaddr(int n, struct sockaddr_ll *have, struct sockaddr_ll *want)
{
	if (have->sll_family != want->sll_family) {
		fail("%d Family mismatch %d/%d", n,
				(int)have->sll_family, (int)want->sll_family);
		return 1;
	}

	if (have->sll_protocol != want->sll_protocol) {
		fail("%d Proto mismatch %d/%d", n,
				(int)have->sll_protocol, (int)want->sll_protocol);
		return 1;
	}

	if (have->sll_ifindex != want->sll_ifindex) {
		fail("%d Index mismatch %d/%d", n,
				have->sll_ifindex, want->sll_ifindex);
		return 1;
	}

	/* all the others are derivatives from dev */
	return 0;
}

int main(int argc, char **argv)
{
	int sk1, sk2;
	struct sockaddr_ll addr, addr1, addr2;
	socklen_t alen;

	test_init(argc, argv);

	sk1 = socket(PF_PACKET, SOCK_RAW, 0);
	if (sk1 < 0) {
		err("Can't create socket 1");
		return 1;
	}

	sk2 = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (sk2 < 0) {
		err("Can't create socket 2");
		return 1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = 1; /* loopback should be 1 in all namespaces */
	if (bind(sk2, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		err("Can't bind socket %m");
		return 1;
	}

	alen = sizeof(addr1);
	if (getsockname(sk1, (struct sockaddr *)&addr1, &alen) < 0) {
		err("Can't get sockname 1");
		return 1;
	}

	alen = sizeof(addr2);
	if (getsockname(sk2, (struct sockaddr *)&addr2, &alen) < 0) {
		err("Can't get sockname 2");
		return 1;
	}

	test_daemon();
	test_waitsig();

	alen = sizeof(addr);
	if (getsockname(sk1, (struct sockaddr *)&addr, &alen) < 0) {
		fail("Can't get sockname 1 rst");
		return 1;
	}

	if (test_sockaddr(1, &addr, &addr1))
		return 1;

	alen = sizeof(addr);
	if (getsockname(sk2, (struct sockaddr *)&addr, &alen) < 0) {
		fail("Can't get sockname 2 rst");
		return 1;
	}

	if (test_sockaddr(2, &addr, &addr2))
		return 1;

	pass();
	return 0;
}
