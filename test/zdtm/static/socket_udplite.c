#include "zdtmtst.h"

const char *test_doc = "static test for UDP socket\n";
const char *test_author = "Pavel Emelyanov <xemul@parallels.com<>\n";

/* Description:
 * Create two tcp socket, server send asynchronous request on
 * read data and client write data after migration
 */

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

static int port = 8890;
static char buf[8];

#define MSG1 "msg1"
#define MSG2 "msg_2"

int main(int argc, char **argv)
{
	int ret, sk1, sk2, sk3, sk4;
	socklen_t len = sizeof(struct sockaddr_in);
	struct sockaddr_in addr1, addr2, addr3, addr4, addr;

	test_init(argc, argv);

	sk1 = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDPLITE);
	if (sk1 < 0) {
		pr_perror("Can't create socket");
		return 1;
	}

	memset(&addr1, 0, sizeof(addr1));
	addr1.sin_family = AF_INET;
	addr1.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr1.sin_port = htons(port);

	ret = bind(sk1, (struct sockaddr *)&addr1, len);
	if (ret < 0) {
		pr_perror("Can't bind socket");
		return 1;
	}

	sk2 = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDPLITE);
	if (sk2 < 0) {
		pr_perror("Can't create socket");
		return 1;
	}

	memset(&addr2, 0, sizeof(addr1));
	addr2.sin_family = AF_INET;
	addr2.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr2.sin_port = htons(port + 1);

	ret = bind(sk2, (struct sockaddr *)&addr2, len);
	if (ret < 0) {
		pr_perror("Can't bind socket");
		return 1;
	}

	ret = connect(sk2, (struct sockaddr *)&addr1, len);
	if (ret < 0) {
		pr_perror("Can't connect");
		return 1;
	}

	sk3 = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDPLITE);
	if (sk3 < 0) {
		pr_perror("Can't create socket");
		return 1;
	}

	memset(&addr3, 0, sizeof(addr3));
	addr3.sin_family = AF_INET;
	addr3.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr3.sin_port = htons(port + 2);

	ret = bind(sk3, (struct sockaddr *)&addr3, len);
	if (ret < 0) {
		pr_perror("Can't bind socket");
		return 1;
	}

	sk4 = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDPLITE);
	if (sk4 < 0) {
		pr_perror("Can't create socket");
		return 1;
	}

	memset(&addr4, 0, sizeof(addr4));
	addr4.sin_family = AF_INET;
	addr4.sin_addr.s_addr = inet_addr("0.0.0.0");
	addr4.sin_port = htons(0);

	ret = bind(sk4, (struct sockaddr *)&addr4, len);
	if (ret < 0) {
		pr_perror("Can't bind socket");
		return 1;
	}

	ret = connect(sk4, (struct sockaddr *)&addr3, len);
	if (ret < 0) {
		pr_perror("Can't connect");
		return 1;
	}

	ret = connect(sk3, (struct sockaddr *)&addr4, len);
	if (ret < 0) {
		pr_perror("Can't connect");
		return 1;
	}

	if (shutdown(sk4, SHUT_RDWR)) {
		pr_perror("Can't shutdown socket");
		return 1;
	}

	if (shutdown(sk3, SHUT_RDWR)) {
		pr_perror("Can't shutdown socket");
		return 1;
	}

	test_daemon();
	test_waitsig();

	ret = sendto(sk1, MSG1, sizeof(MSG1), 0, (struct sockaddr *)&addr2, len);
	if (ret < 0) {
		fail("Can't send");
		return 1;
	}

	ret = send(sk2, MSG2, sizeof(MSG2), 0);
	if (ret < 0) {
		fail("Can't send C");
		return 1;
	}

	ret = recvfrom(sk1, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &len);
	if (ret <= 0) {
		fail("Can't recv C");
		return 1;
	}

	if (len != sizeof(struct sockaddr_in) || memcmp(&addr2, &addr, len)) {
		fail("Wrong peer C");
		return 1;
	}

	if (ret != sizeof(MSG2) || memcmp(buf, MSG2, ret)) {
		fail("Wrong message C");
		return 1;
	}

	ret = recvfrom(sk2, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &len);
	if (ret <= 0) {
		fail("Can't recv");
		return 1;
	}

	if (len != sizeof(struct sockaddr_in) || memcmp(&addr1, &addr, len)) {
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
