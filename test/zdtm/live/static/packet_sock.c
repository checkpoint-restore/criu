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
#include <linux/version.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#define SK_RESERVE	8
#define DEF_FANOUT	13

#ifndef PACKET_FANOUT
#define PACKET_FANOUT	18
#endif

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

#ifndef MAX_ADDR_LEN
#define MAX_ADDR_LEN	32
#endif

struct packet_mreq_max {
	int             mr_ifindex;
	unsigned short  mr_type;
	unsigned short  mr_alen;
	unsigned char   mr_address[MAX_ADDR_LEN];
};

#define LO_ADDR_LEN	6

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)

struct tpacket_req3 {
	unsigned int tp_block_size;
	unsigned int tp_block_nr;
	unsigned int tp_frame_size;
	unsigned int tp_frame_nr;
	unsigned int tp_retire_blk_tov;
	unsigned int tp_sizeof_priv;
	unsigned int tp_feature_req_word;
};

#endif

int main(int argc, char **argv)
{
	int sk1, sk2;
	struct sockaddr_ll addr, addr1, addr2;
	socklen_t alen;
	int ver, rsv, yes;
	struct packet_mreq_max mreq;
	struct tpacket_req3 ring;

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

	ver = TPACKET_V2;
	if (setsockopt(sk1, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver)) < 0) {
		err("Can't set version %m");
		return 1;
	}

	yes = 1;
	if (setsockopt(sk1, SOL_PACKET, PACKET_AUXDATA, &yes, sizeof(yes)) < 0) {
		err("Can't set auxdata %m");
		return 1;
	}

	memset(&ring, 0, sizeof(ring));
	ring.tp_block_size = 4096;
	ring.tp_block_nr = 1;
	ring.tp_frame_size = 1024;
	ring.tp_frame_nr = 4;
	if (setsockopt(sk1, SOL_PACKET, PACKET_RX_RING, &ring, sizeof(ring)) < 0) {
		err("Can't set rx ring %m");
		return 1;
	}

	rsv = SK_RESERVE;
	if (setsockopt(sk2, SOL_PACKET, PACKET_RESERVE, &rsv, sizeof(rsv)) < 0) {
		err("Can't set reserve %m");
		return 1;
	}

	yes = 1;
	if (setsockopt(sk2, SOL_PACKET, PACKET_ORIGDEV, &yes, sizeof(yes)) < 0) {
		err("Can't set origdev %m");
		return 1;
	}

	yes = DEF_FANOUT;
	if (setsockopt(sk2, SOL_PACKET, PACKET_FANOUT, &yes, sizeof(yes)) < 0) {
		err("Can't configure fanout %m");
		return 1;
	}

	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = 1;
	mreq.mr_type = PACKET_MR_PROMISC;
	if (setsockopt(sk1, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
		err("Can't add promisc member %m");
		return 1;
	}

	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = 1;
	mreq.mr_type = PACKET_MR_UNICAST;
	mreq.mr_alen = LO_ADDR_LEN;
	if (setsockopt(sk2, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
		err("Can't add ucast member %m");
		return 1;
	}

	memset(&ring, 0, sizeof(ring));
	ring.tp_block_size = 4096;
	ring.tp_block_nr = 1;
	ring.tp_frame_size = 1024;
	ring.tp_frame_nr = 4;
	if (setsockopt(sk2, SOL_PACKET, PACKET_TX_RING, &ring, sizeof(ring)) < 0) {
		err("Can't set tx ring %m");
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

	alen = sizeof(ver);
	if (getsockopt(sk1, SOL_PACKET, PACKET_VERSION, &ver, &alen) < 0) {
		fail("Can't get sockopt ver %m");
		return 1;
	}

	if (ver != TPACKET_V2) {
		fail("Version mismatch have %d, want %d\n", ver, TPACKET_V2);
		return 1;
	}

	alen = sizeof(yes);
	if (getsockopt(sk1, SOL_PACKET, PACKET_AUXDATA, &yes, &alen) < 0) {
		fail("Can't get sockopt auxdata %m");
		return 1;
	}

	if (yes != 1) {
		fail("Auxdata not ON");
		return 1;
	}

	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = 1;
	mreq.mr_type = PACKET_MR_PROMISC;
	if (setsockopt(sk1, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
		fail("Promisc member not kept");
		return 1;
	}

	alen = sizeof(yes);
	if (getsockopt(sk1, SOL_PACKET, PACKET_FANOUT, &yes, &alen) < 0) {
		fail("Can't read fanout back %m");
		return 1;
	}

	if (yes != 0) {
		fail("Fanout screwed up to %x", yes);
		return 1;
	}

	alen = sizeof(addr);
	if (getsockname(sk2, (struct sockaddr *)&addr, &alen) < 0) {
		fail("Can't get sockname 2 rst");
		return 1;
	}

	if (test_sockaddr(2, &addr, &addr2))
		return 1;

	alen = sizeof(rsv);
	if (getsockopt(sk2, SOL_PACKET, PACKET_RESERVE, &rsv, &alen) < 0) {
		fail("Can't get sockopt rsv %m");
		return 1;
	}

	alen = sizeof(yes);
	if (getsockopt(sk2, SOL_PACKET, PACKET_ORIGDEV, &yes, &alen) < 0) {
		fail("Can't get sockopt origdev %m");
		return 1;
	}

	if (yes != 1) {
		fail("OrigDev not ON");
		return 1;
	}

	if (rsv != SK_RESERVE) {
		fail("Reserve mismatch have %d, want %d\n", rsv, SK_RESERVE);
		return 1;
	}

	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = 1;
	mreq.mr_type = PACKET_MR_UNICAST;
	mreq.mr_alen = LO_ADDR_LEN;
	if (setsockopt(sk2, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
		fail("Ucast member not kept");
		return 1;
	}

	alen = sizeof(yes);
	if (getsockopt(sk2, SOL_PACKET, PACKET_FANOUT, &yes, &alen) < 0) {
		fail("Can't read fanout2 back %m");
		return 1;
	}

	if (yes != DEF_FANOUT) {
		fail("Fanout2 screwed up to %x", yes);
		return 1;
	}

	pass();
	return 0;
}
