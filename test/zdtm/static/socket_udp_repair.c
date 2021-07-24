#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/udp.h>

#include "zdtmtst.h"

const char *test_doc = "Test for C/R UDP socket's queue\n";
const char *test_author = "Bui Quang Minh <minhquangbui99@gmail.com>\n";

/* Description:
 * Checkpoint/restore a corked UDP socket with 2 packets in send queue
 * and 2 packets in recv queue
 */

#define PORT 3000

#define MSG1_1 "msg1_1"
#define MSG1_2 "msg1_2"
#define MSG2   "msg2"
#define MSG3   "msg_3"

int main(int argc, char **argv)
{
	int ret, sk1, sk2, sk3, aux;
	struct sockaddr_in addr1, addr2, addr3, addr;
	unsigned int addr_len;
	char recv_buffer[256], buffer[256];

	test_init(argc, argv);

	sk1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sk1 < 0) {
		pr_perror("Can't create socket");
		return 1;
	}

	sk2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sk2 < 0) {
		pr_perror("Can't create socket");
		return 1;
	}

	sk3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sk3 < 0) {
		pr_perror("Can't create socket");
		return 1;
	}

	memset(&addr1, 0, sizeof(addr1));
	addr1.sin_family = AF_INET;
	addr1.sin_port = htons(PORT);
	addr1.sin_addr.s_addr = inet_addr("127.0.0.1");
	ret = bind(sk1, (struct sockaddr *)&addr1, sizeof(addr1));
	if (ret < 0) {
		pr_perror("Can't bind socket");
		return 1;
	}

	memset(&addr2, 0, sizeof(addr2));
	addr2.sin_family = AF_INET;
	addr2.sin_port = htons(PORT + 1);
	addr2.sin_addr.s_addr = inet_addr("127.0.0.1");
	ret = bind(sk2, (struct sockaddr *)&addr2, sizeof(addr2));
	if (ret < 0) {
		pr_perror("Can't bind socket");
		return 1;
	}

	memset(&addr3, 0, sizeof(addr3));
	addr3.sin_family = AF_INET;
	addr3.sin_port = htons(PORT + 2);
	addr3.sin_addr.s_addr = inet_addr("127.0.0.1");
	ret = bind(sk3, (struct sockaddr *)&addr3, sizeof(addr3));
	if (ret < 0) {
		pr_perror("Can't bind socket");
		return 1;
	}

	ret = sendto(sk2, MSG2, sizeof(MSG2), 0, (struct sockaddr *)&addr1, sizeof(addr1));
	if (ret < 0) {
		pr_perror("Can't send");
		return 1;
	}

	ret = sendto(sk3, MSG3, sizeof(MSG3), 0, (struct sockaddr *)&addr1, sizeof(addr1));
	if (ret < 0) {
		pr_perror("Can't send");
		return 1;
	}

	aux = 1;
	if (setsockopt(sk1, SOL_UDP, UDP_CORK, &aux, sizeof(aux))) {
		pr_perror("Can't set UDP_CORK");
		return 1;
	}

	ret = sendto(sk1, MSG1_1, sizeof(MSG1_1), 0, (struct sockaddr *)&addr3, sizeof(addr3));
	if (ret < 0) {
		pr_perror("Can't send");
		return 1;
	}

	ret = sendto(sk1, MSG1_2, sizeof(MSG1_2), 0, (struct sockaddr *)&addr3, sizeof(addr3));
	if (ret < 0) {
		pr_perror("Can't send");
		return 1;
	}

	close(sk2);

	test_daemon();
	test_waitsig();

	aux = 0;
	if (setsockopt(sk1, SOL_UDP, UDP_CORK, &aux, sizeof(aux))) {
		fail("Can't unset UDP_CORK");
		return 1;
	}

	addr_len = sizeof(addr);
	ret = recvfrom(sk3, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&addr, &addr_len);
	if (ret < 0) {
		fail("Can't receive corked packet");
		return 1;
	}

	memcpy(buffer, MSG1_1, sizeof(MSG1_1));
	memcpy(buffer + sizeof(MSG1_1), MSG1_2, sizeof(MSG1_2));
	if (ret != sizeof(MSG1_1) + sizeof(MSG1_2) || memcmp(recv_buffer, buffer, ret)) {
		fail("Message 1 mismatch");
		return 1;
	}

	if (addr_len != sizeof(struct sockaddr_in) || memcmp(&addr1, &addr, addr_len)) {
		fail("Wrong peer");
		return 1;
	}

	ret = recvfrom(sk1, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&addr, &addr_len);
	if (ret < 0) {
		fail("Can't receive MSG2");
		return 1;
	}

	if (ret != sizeof(MSG2) || memcmp(recv_buffer, MSG2, sizeof(MSG2))) {
		fail("Message 2 mismatch");
		return 1;
	}

	if (addr_len != sizeof(struct sockaddr_in) || memcmp(&addr2, &addr, addr_len)) {
		fail("Wrong peer 2");
		return 1;
	}

	ret = recvfrom(sk1, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&addr, &addr_len);
	if (ret < 0) {
		fail("Can't receive MSG3");
		return 1;
	}

	if (ret != sizeof(MSG3) || memcmp(recv_buffer, MSG3, sizeof(MSG3))) {
		fail("Message 3 mismatch");
		return 1;
	}

	if (addr_len != sizeof(struct sockaddr_in) || memcmp(&addr3, &addr, addr_len)) {
		fail("Wrong peer 3");
		return 1;
	}

	pass();

	return 0;
}
