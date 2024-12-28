#include "zdtmtst.h"

const char *test_doc = "static test for ICMP socket\n";
const char *test_author = "समीर सिंह Sameer Singh <lumarzeli30@gmail.com>\n";

/* Description:
 * Send a ping to localhost using ICMP socket
 */

#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#if defined(ZDTM_IPV6)
#include <netinet/icmp6.h>
#else
#include <netinet/ip_icmp.h>
#endif
#include <arpa/inet.h>
#include <sys/time.h>
#include <netdb.h>

#include "sysctl.h"

#define PACKET_SIZE  64
#define RECV_TIMEOUT 1

static int echo_id = 1234;

#if defined(ZDTM_IPV6)
#define TEST_ICMP_ECHOREPLY ICMP6_ECHOREPLY
#else
#define TEST_ICMP_ECHOREPLY ICMP_ECHOREPLY
#endif
int main(int argc, char **argv)
{
	int ret, sock, seq = 0;
	char packet[PACKET_SIZE], recv_packet[PACKET_SIZE];

	struct timeval tv;
#if defined(ZDTM_IPV6)
	struct sockaddr_in6 addr, recv_addr;
#else
	struct icmphdr icmp_header, *icmp_reply;
#endif
	struct sockaddr_in addr, recv_addr;
	socklen_t addr_len;

	// Allow GIDs 0-58468 to open an unprivileged ICMP socket
	if (sysctl_write_str("/proc/sys/net/ipv4/ping_group_range", "0 58468"))
		return -1;

	test_init(argc, argv);

#if defined(ZDTM_IPV6)
	sock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
#else
	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_ICMP);
#endif
	if (sock < 0) {
		pr_perror("Can't create socket");
		return 1;
	}

	tv.tv_sec = RECV_TIMEOUT;
	tv.tv_usec = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		pr_perror("Can't set socket option");
		return 1;
	}

	memset(&addr, 0, sizeof(addr));
	memset(&icmp_header, 0, sizeof(icmp_header));
#if defined(ZDTM_IPV6)
	addr.sin6_family = AF_INET6;
	inet_pton(AF_INET6, "::1", &addr.sin6_addr);

	icmp_header.icmp6_type = ICMP6_ECHO_REQUEST;
	icmp_header.icmp6_code = 0;
	icmp_header.icmp6_id = echo_id;
	icmp_header.icmp6_seq = seq;
#else
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	icmp_header.type = ICMP_ECHO;
	icmp_header.code = 0;
	icmp_header.un.echo.id = echo_id;
	icmp_header.un.echo.sequence = seq;
#endif

	memcpy(packet, &icmp_header, sizeof(icmp_header));
	memset(packet + sizeof(icmp_header), 0xa5,
	       PACKET_SIZE - sizeof(icmp_header));

	test_daemon();
	test_waitsig();

	ret = sendto(sock, packet, PACKET_SIZE, 0,
		     (struct sockaddr *)&addr, sizeof(addr));

	if (ret < 0) {
		fail("Can't send");
		return 1;
	}

	addr_len = sizeof(recv_addr);

	ret = recvfrom(sock, recv_packet, sizeof(recv_packet), 0,
		       (struct sockaddr *)&recv_addr, &addr_len);

	if (ret < 0) {
		fail("Can't recv");
		return 1;
	}

	icmp_reply = (struct icmphdr *)recv_packet;

	if (icmp_reply->type != ICMP_ECHOREPLY) {
		fail("Got no ICMP_ECHO_REPLY");
		return 1;
	}

	close(sock);

	pass();
	return 0;
}
