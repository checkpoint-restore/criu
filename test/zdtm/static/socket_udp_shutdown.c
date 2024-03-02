#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h> /* for sockaddr_in and inet_ntoa() */
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc = "static test for UDP shutdown'ed socket";
const char *test_author = "Cyrill Gorcunov <gorcunov@virtuozzo.com>";

static int port = 8881;

#define MSG1 "msg1"

int main(int argc, char **argv)
{
	socklen_t len = sizeof(struct sockaddr_in);
	struct sockaddr_in addr1, addr2, addr;
	int ret, sk1, sk2;
	char buf[512];

	test_init(argc, argv);

	sk1 = socket(PF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
	sk2 = socket(PF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
	if (sk1 < 0 || sk2 < 0) {
		pr_perror("Can't create socket");
		exit(1);
		return 1;
	}

	memset(&addr1, 0, sizeof(addr1));
	memset(&addr2, 0, sizeof(addr1));

	addr1.sin_family = AF_INET;
	addr1.sin_addr.s_addr = inet_addr("127.0.0.10");
	addr1.sin_port = htons(port);

	addr2.sin_family = AF_INET;
	addr2.sin_addr.s_addr = inet_addr("127.0.0.10");
	addr2.sin_port = htons(port + 1);

	if (bind(sk1, (struct sockaddr *)&addr1, len) < 0 || bind(sk2, (struct sockaddr *)&addr2, len) < 0) {
		pr_perror("Can't bind socket");
		return 1;
	}

	if (connect(sk1, (struct sockaddr *)&addr2, len) || connect(sk2, (struct sockaddr *)&addr1, len)) {
		pr_perror("Can't connect");
		return 1;
	}

	if (shutdown(sk1, SHUT_WR) || shutdown(sk2, SHUT_RD)) {
		pr_perror("Can't shutdown");
		return 1;
	}

	ret = sendto(sk2, MSG1, sizeof(MSG1), 0, (struct sockaddr *)&addr1, len);
	if (ret < 0) {
		pr_perror("Can't send");
		return 1;
	}

	ret = recvfrom(sk1, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &len);
	if (ret <= 0) {
		pr_perror("Can't receive data");
		return 1;
	}

	if (len != sizeof(struct sockaddr_in) || memcmp(&addr2, &addr, len)) {
		pr_err("Data received from wrong peer\n");
		return 1;
	}

	if (ret != sizeof(MSG1) || memcmp(buf, MSG1, ret)) {
		pr_err("Wrong message received\n");
		return 1;
	}

	test_daemon();
	test_waitsig();

	ret = sendto(sk2, MSG1, sizeof(MSG1), 0, (struct sockaddr *)&addr1, len);
	if (ret < 0) {
		pr_perror("Can't send");
		return 1;
	}

	ret = recvfrom(sk1, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &len);
	if (ret <= 0) {
		pr_perror("Can't receive data");
		return 1;
	}

	if (len != sizeof(struct sockaddr_in) || memcmp(&addr2, &addr, len)) {
		pr_err("Data received from wrong peer\n");
		return 1;
	}

	if (ret != sizeof(MSG1) || memcmp(buf, MSG1, ret)) {
		pr_err("Wrong message received\n");
		return 1;
	}

	ret = sendto(sk1, MSG1, sizeof(MSG1), 0, (struct sockaddr *)&addr2, len);
	if (ret >= 0) {
		fail("Sent to write-shutdown'ed socket");
		return 1;
	}

	pass();
	return 0;
}
