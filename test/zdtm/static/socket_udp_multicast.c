#define _DEFAULT_SOURCE

#include "zdtmtst.h"
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>

const char *test_doc = "Test for UDP multicast socket - DOCUMENTS that CRIU does NOT restore IP_ADD_MEMBERSHIP\n";
const char *test_author = "Shailja Shaktawat";

#define MCAST_ADDR "224.0.0.250"
#define PORT	   8888
#define MSG1	   "msg1"

static int port = PORT;
static char buf[8];

int main(int argc, char **argv)
{
	int ret, recv_sk, send_sk;
	int yes = 1;
	unsigned char loop = 1;
	socklen_t len = sizeof(struct sockaddr_in);
	struct sockaddr_in mcast_addr, recv_addr, send_addr, from_addr;
	struct ip_mreqn mreq;
	struct timeval tv;

	test_init(argc, argv);

	/* Enable multicast routing on loopback - CRITICAL! */
	system("ip route add 224.0.0.0/4 dev lo 2>/dev/null");

	/* Receiver socket setup */
	recv_sk = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (recv_sk < 0) {
		pr_perror("Can't create receiver socket");
		return 1;
	}

	if (setsockopt(recv_sk, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
		pr_perror("Can't set SO_REUSEADDR");
		return 1;
	}

	memset(&recv_addr, 0, sizeof(recv_addr));
	recv_addr.sin_family = AF_INET;
	recv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	recv_addr.sin_port = htons(PORT);

	ret = bind(recv_sk, (struct sockaddr *)&recv_addr, len);
	if (ret < 0) {
		pr_perror("Can't bind receiver socket");
		return 1;
	}

	/* Join multicast group */
	memset(&mreq, 0, sizeof(mreq));
	mreq.imr_multiaddr.s_addr = inet_addr(MCAST_ADDR);
	mreq.imr_ifindex = if_nametoindex("lo");

	if (setsockopt(recv_sk, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
		pr_perror("Can't join multicast group");
		return 1;
	}

	/* Sending socket setup */
	send_sk = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (send_sk < 0) {
		pr_perror("Can't create sender socket");
		return 1;
	}

	/* Enable multicast loopback so we can send to ourselves */
	if (setsockopt(send_sk, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
		pr_perror("Can't set multicast loopback");
		return 1;
	}

	memset(&send_addr, 0, sizeof(send_addr));
	send_addr.sin_family = AF_INET;
	send_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	send_addr.sin_port = htons(port + 1);

	ret = bind(send_sk, (struct sockaddr *)&send_addr, len);
	if (ret < 0) {
		pr_perror("Can't bind sender socket");
		return 1;
	}

	memset(&mcast_addr, 0, sizeof(mcast_addr));
	mcast_addr.sin_family = AF_INET;
	mcast_addr.sin_addr.s_addr = inet_addr(MCAST_ADDR);
	mcast_addr.sin_port = htons(PORT);

	/* Set receive timeout to avoid hanging */
	tv.tv_sec = 3;
	tv.tv_usec = 0;
	if (setsockopt(recv_sk, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		pr_perror("Can't set receive timeout");
		return 1;
	}

	test_daemon();
	test_waitsig();

	usleep(100000);

	/* Send from sender to multicast, receive on receiver */
	ret = sendto(send_sk, MSG1, sizeof(MSG1), 0,
		     (struct sockaddr *)&mcast_addr, len);
	if (ret < 0) {
		pr_perror("Can't send multicast");
		return 1;
	}

	ret = recvfrom(recv_sk, buf, sizeof(buf) - 1, 0,
		       (struct sockaddr *)&from_addr, &len);

	if (ret <= 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			fail("Multicast membership NOT restored (expected - CRIU doesn't support IP_ADD_MEMBERSHIP)");
		} else {
			pr_perror("Error receiving");
			return 1;
		}
	} else {
		if (ret != sizeof(MSG1) || memcmp(buf, MSG1, ret)) {
			fail("Wrong multicast message");
			goto out;
		}
		pass();
	}

	/* Drop multicast membership (only if it was restored) */
	if (setsockopt(recv_sk, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
		test_msg("Can't drop multicast membership (expected if not restored)\n");

out:
	close(send_sk);
	close(recv_sk);

	return 0;
}