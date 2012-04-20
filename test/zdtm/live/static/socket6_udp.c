#include "zdtmtst.h"

const char *test_doc = "Static test for IP6/UDP socket\n";
const char *test_author = "Cyrill Gorcunov <gorcunov@openvz.org>\n";

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>  /* for sockaddr_in and inet_ntoa() */
#include <wait.h>

static int port = 8880;
static char buf[64];

#define MSG1 "msg1"
#define MSG2 "msg_2"

int main(int argc, char **argv)
{
	int ret, sk1, sk2;
	socklen_t len = sizeof(struct sockaddr_in6);
	struct sockaddr_in6 addr1, addr2, addr;

	test_init(argc, argv);

	sk1 = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sk1 < 0) {
		err("Can't create socket");
		return 1;
	}

	memset(&addr1, 0, sizeof(addr1));
	addr1.sin6_family = AF_INET6;
	addr1.sin6_port = htons(port);
	inet_pton(AF_INET6, "::1", &addr1.sin6_addr);

	ret = bind(sk1, (struct sockaddr *)&addr1, len);
	if (ret < 0) {
		err("Can't bind socket");
		return 1;
	}

	sk2 = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sk2 < 0) {
		err("Can't create socket");
		return 1;
	}

	memset(&addr2, 0, sizeof(addr2));
	addr2.sin6_family = AF_INET6;
	addr2.sin6_port = htons(port+1);
	inet_pton(AF_INET6, "::1", &addr2.sin6_addr);

	ret = bind(sk2, (struct sockaddr *)&addr2, len);
	if (ret < 0) {
		err("Can't bind socket");
		return 1;
	}

	ret = connect(sk2, (struct sockaddr *)&addr1, len);
	if (ret < 0) {
		err("Can't connect");
		return 1;
	}

	test_daemon();
	test_waitsig();

	ret = sendto(sk1, MSG1, sizeof(MSG1), 0,
			(struct sockaddr *)&addr2, len);
	if (ret < 0) {
		fail("Can't send");
		return 1;
	}

	ret = send(sk2, MSG2, sizeof(MSG2), 0);
	if (ret < 0) {
		fail("Can't send C");
		return 1;
	}

	ret = recvfrom(sk1, buf, sizeof(buf), MSG_DONTWAIT,
			(struct sockaddr *)&addr, &len);
	if (ret <= 0) {
		fail("Can't recv C");
		return 1;
	}

	if (len != sizeof(struct sockaddr_in6) || memcmp(&addr2, &addr, len)) {
		fail("Wrong peer C");
		return 1;
	}

	if (ret != sizeof(MSG2) || memcmp(buf, MSG2, ret)) {
		fail("Wrong message C");
		return 1;
	}

	ret = recvfrom(sk2, buf, sizeof(buf), MSG_DONTWAIT,
			(struct sockaddr *)&addr, &len);
	if (ret <= 0) {
		fail("Can't recv");
		return 1;
	}

	if (len != sizeof(struct sockaddr_in6) || memcmp(&addr1, &addr, len)) {
		fail("Wrong peer");
		return 1;
	}

	if (ret != sizeof(MSG1) || memcmp(buf, MSG1, ret)) {
		fail("Wrong message");
		return 1;
	}

	pass();
	return 0;
}
