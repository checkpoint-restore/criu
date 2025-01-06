#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/stat.h>

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include <limits.h>
#include <fcntl.h>

#include "zdtmtst.h"

/*
 * Some code snippets are taken from
 * http://www.binarytides.com/raw-udp-sockets-c-linux/
 */

const char *test_doc = "Test RAW sockets (IPv4,6)\n";
const char *test_author = "Cyrill Gorcunov <gorcunov@openvz.org>";

#ifndef SO_IP_SET
#define SO_IP_SET 83
#endif

#ifndef IP_SET_OP_VERSION
#define IP_SET_OP_VERSION 0x00000100 /* Ask kernel version */
#endif

#define pr_debug(format, arg...) test_msg("DBG: %s:%d: " format, __FILE__, __LINE__, ##arg)

struct ip_set_req_version {
	unsigned int op;
	unsigned int version;
};

struct pseudo_header {
	uint32_t source_address;
	uint32_t dest_address;
	uint8_t placeholder;
	uint8_t protocol;
	uint16_t udp_length;
};

static int stop_icmp(int sk_icmp, int sk_icmpv6)
{
	struct icmp6_filter filter6 = {};
	struct icmp_filter filter = {};
	socklen_t aux;
	int ret = 0;

	aux = sizeof(filter);
	ret = getsockopt(sk_icmp, SOL_RAW, ICMP_FILTER, &filter, &aux);
	if (ret < 0) {
		pr_perror("stop_icmp: Can't fetch icmp filter");
		return ret;
	}

	if (filter.data != (1 << ICMP_TIMESTAMP)) {
		pr_err("data mismatch on icmp filter %d != %d\n", filter.data, (1 << ICMP_TIMESTAMP));
		return -1;
	}

	aux = sizeof(filter6);
	ret = getsockopt(sk_icmpv6, SOL_ICMPV6, ICMPV6_FILTER, &filter6, &aux);
	if (ret < 0) {
		pr_perror("stop_icmp: Can't fetch icmpv6 filter");
		return ret;
	}

	if (filter6.data[0] != (1 << ICMP_TIMESTAMP)) {
		pr_err("data mismatch on icmp filter %d != %d\n", filter6.data[0], (1 << ICMP_TIMESTAMP));
		return -1;
	}

	return ret;
}

static int start_icmp(int sk_icmp, int sk_icmpv6, const char *a4, const char *a6, int port)
{
	struct sockaddr_in addr_client;
	struct icmp6_filter filter6 = {};
	struct icmp_filter filter = {};
	int ret = 0;

	memset(&addr_client, 0, sizeof(addr_client));

	addr_client.sin_family = AF_INET;
	addr_client.sin_port = htons(port);
	addr_client.sin_addr.s_addr = inet_addr(a4);

	ret = bind(sk_icmp, (struct sockaddr *)&addr_client, sizeof(addr_client));
	if (ret < 0) {
		pr_perror("start_icmp: Can't bind RAW client socket");
		return ret;
	}
	pr_debug("start_icmp: Bound sk_icmp\n");

	filter.data = (1 << ICMP_TIMESTAMP);
	ret = setsockopt(sk_icmp, SOL_RAW, ICMP_FILTER, &filter, sizeof(filter));
	if (ret < 0) {
		pr_perror("start_icmp: Can't setup icmp filter");
		return ret;
	}

	filter6.data[0] = (1 << ICMP_TIMESTAMP);
	ret = setsockopt(sk_icmpv6, SOL_ICMPV6, ICMPV6_FILTER, &filter6, sizeof(filter6));
	if (ret < 0) {
		pr_perror("start_icmp: Can't setup icmpv6 filter");
		return ret;
	}

	return ret;
}

static unsigned short csum(unsigned short *ptr, int nbytes)
{
	unsigned short oddbyte;
	register short answer;
	register long sum;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}

	if (nbytes == 1) {
		oddbyte = 0;
		*((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short)~sum;

	return answer;
}

/*
 * Just create IPv6/IPv6 sockets with any protos
 * to make sure criu won't BUG on unknown proto.
 */
static void raw_socks_storm(void)
{
	int sk4[IPPROTO_MAX];
	int sk6[IPPROTO_MAX];
	size_t i;

	for (i = 1; i < ARRAY_SIZE(sk4); i++) {
		sk4[i] = socket(PF_INET, SOCK_RAW | SOCK_NONBLOCK, i);
		if (sk4[i] >= 0)
			test_msg("Created IPv4 proto %zd: %d\n", i, sk4[i]);
	}

	for (i = 1; i < ARRAY_SIZE(sk6); i++) {
		sk6[i] = socket(PF_INET6, SOCK_RAW | SOCK_NONBLOCK, i);
		if (sk6[i] >= 0)
			test_msg("Created IPv6 proto %zd: %d\n", i, sk6[i]);
	}
}

int main(int argc, char *argv[])
{
	const char string_data[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	const char string_client_ip[] = "127.0.0.12";
	const char string_serv_ip[] = "127.0.0.10";
	const char string_client_icmp_ip[] = "127.0.0.14";
	const char string_client_icmpv6_ip[] = "::14";
	char datagram[512], *data, *pseudogram;
	char receiver[512];

	struct ip_set_req_version req_version;
	socklen_t size = sizeof(req_version);

	int sk_udp, sk_udp_serv;
	int sk_raw, sk6_raw;
	int sk_icmp, sk_icmpv6;

	struct udphdr *udph = (struct udphdr *)(datagram + sizeof(struct ip));
	struct iphdr *iph = (struct iphdr *)datagram;
	struct sockaddr_in addr_serv, addr_client;
	struct pseudo_header psh;

	int port_client = 8080;
	int port_serv = 8081;

	int psize, one = 1;
	const int *val = &one;

	socklen_t len = sizeof(struct sockaddr_in);
	int ret, status;

	pid_t pid;

	task_waiter_t waiter;

	test_init(argc, argv);

	task_waiter_init(&waiter);

	sk_raw = socket(PF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_RAW);
	if (sk_raw < 0) {
		pr_perror("Can't create IPv4 raw socket");
		exit(1);
	}
	pr_debug("sk_raw %d\n", sk_raw);

	/* Simply to make sure it can be recreated on restore */
	sk6_raw = socket(PF_INET6, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_RAW);
	if (sk6_raw < 0) {
		pr_perror("Can't create IPv6 raw socket");
		exit(1);
	}
	pr_debug("sk6_raw %d\n", sk6_raw);

	sk_udp = socket(PF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_UDP);
	if (sk_udp < 0) {
		pr_perror("Can't create IPv4 raw-udp socket");
		exit(1);
	}
	pr_debug("sk_udp %d\n", sk_udp);

	sk_icmp = socket(PF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP);
	if (sk_icmp < 0) {
		pr_perror("Can't create IPv4 raw icmp socket");
		exit(1);
	}
	pr_debug("sk_icmp %d\n", sk_icmp);

	sk_icmpv6 = socket(PF_INET6, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMPV6);
	if (sk_icmpv6 < 0) {
		pr_perror("Can't create IPv6 raw icmpv6 socket");
		exit(1);
	}
	pr_debug("sk_icmpv6 %d\n", sk_icmpv6);

	sk_udp_serv = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sk_udp_serv < 0) {
		pr_perror("Can't create DGRAM server socket");
		exit(1);
	}
	pr_debug("sk_udp_serv %d\n", sk_udp_serv);

	memset(datagram, 0, sizeof(datagram));
	memset(receiver, 0, sizeof(receiver));
	memset(&addr_serv, 0, sizeof(addr_serv));
	memset(&addr_client, 0, sizeof(addr_client));

	addr_client.sin_family = AF_INET;
	addr_client.sin_port = htons(port_client);
	addr_client.sin_addr.s_addr = inet_addr(string_client_ip);

	addr_serv.sin_family = AF_INET;
	addr_serv.sin_port = htons(port_serv);
	addr_serv.sin_addr.s_addr = inet_addr(string_serv_ip);

	ret = bind(sk_udp_serv, (struct sockaddr *)&addr_serv, sizeof(addr_serv));
	if (ret < 0) {
		pr_perror("Can't bind DGRAM server socket");
		return 1;
	}
	pr_debug("Bound sk_udp_serv\n");

	ret = bind(sk_udp, (struct sockaddr *)&addr_client, sizeof(addr_client));
	if (ret < 0) {
		pr_perror("Can't bind DGRAM client socket");
		return 1;
	}
	pr_debug("Bound sk_udp\n");

	if (start_icmp(sk_icmp, sk_icmpv6, string_client_icmp_ip, string_client_icmpv6_ip, port_client))
		return 1;

	data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
	strcpy(data, string_data);

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + strlen(string_data);
	iph->id = htonl(54321);
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;
	iph->saddr = inet_addr(string_client_ip);
	iph->daddr = addr_serv.sin_addr.s_addr;
	iph->check = csum((unsigned short *)datagram, sizeof(struct iphdr));

	udph->source = htons(port_client);
	udph->dest = htons(port_serv);
	udph->len = htons(8 + strlen(data));
	udph->check = 0;

	psh.source_address = inet_addr(string_client_ip);
	psh.dest_address = addr_serv.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_UDP;
	psh.udp_length = htons(sizeof(struct udphdr) + strlen(string_data));

	psize = sizeof(psh) + sizeof(struct udphdr) + strlen(string_data);
	pseudogram = malloc(psize);
	if (!pseudogram) {
		pr_err("No free memory\n");
		exit(1);
	}

	memcpy(pseudogram, (char *)&psh, sizeof(psh));
	memcpy(pseudogram + sizeof(psh), udph, sizeof(*udph) + strlen(string_data));

	udph->check = csum((unsigned short *)pseudogram, psize);
	free(pseudogram);

	if (setsockopt(sk_udp, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
		pr_perror("Error setting IP_HDRINCL");
		exit(1);
	}

	pid = test_fork();
	if (pid == 0) {
		task_waiter_wait4(&waiter, 2);
		pr_debug("Gonna read data\n");
		ret = recvfrom(sk_udp_serv, receiver, sizeof(receiver), 0, (struct sockaddr *)&addr_client, &len);
		if (ret < 0) {
			task_waiter_complete(&waiter, 2);
			fail("Can't read data");
			exit(1);
		}
		receiver[ret] = '\0';
		pr_debug("Read %d bytes\n", ret);

		task_waiter_complete(&waiter, 3);

		if (strcmp(receiver, string_data)) {
			pr_err("Data mismatch (got %s but expected %s)\n", receiver, string_data);
			exit(1);
		} else
			pr_debug("Data match\n");
		exit(0);
	} else if (pid < 0) {
		pr_err("Can't fork\n");
		exit(1);
	}

	raw_socks_storm();

	test_daemon();
	test_waitsig();

	if (sendto(sk_udp, datagram, iph->tot_len, 0, (struct sockaddr *)&addr_serv, sizeof(addr_serv)) < 0) {
		kill(pid, SIGKILL);
		fail("Can't send RAW data");
		exit(1);
	}

	task_waiter_complete(&waiter, 2);
	pr_debug("Sent %d bytes\n", (int)iph->tot_len);
	task_waiter_wait4(&waiter, 3);

	ret = wait(&status);
	if (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status)) {
		kill(pid, SIGKILL);
		fail("Failed waiting server");
		exit(1);
	}

	req_version.op = IP_SET_OP_VERSION;
	ret = getsockopt(sk_raw, SOL_IP, SO_IP_SET, &req_version, &size);
	if (ret) {
		pr_perror("xt_set getsockopt");
		if (errno != ENOPROTOOPT) {
			fail("Can't fetch SO_IP_SET");
			exit(1);
		}
	} else
		test_msg("SO_IP_SET version = %d\n", req_version.version);

	if (stop_icmp(sk_icmp, sk_icmpv6)) {
		fail("Failed on ICMP sockets");
		exit(1);
	}

	pass();
	return 0;
}
