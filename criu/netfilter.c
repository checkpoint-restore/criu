#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <stdlib.h>

#if defined(CONFIG_HAS_NFTABLES_LIB_API_0) || defined(CONFIG_HAS_NFTABLES_LIB_API_1)
#include <nftables/libnftables.h>
#endif

#include "../soccr/soccr.h"

#include "util.h"
#include "common/list.h"
#include "files.h"
#include "netfilter.h"
#include "sockets.h"
#include "sk-inet.h"
#include "kerndat.h"

static char buf[512];

#define NFTABLES_CONN_CMD "add element inet CRIU conns%c { %s . %d . %s . %d }"

/*
 * Need to configure simple netfilter rules for blocking connections
 * Any brave soul to write it using xtables-devel?
 */

#define IPTABLES_CONN_CMD                       \
	"%s %s -t filter %s %s --protocol tcp " \
	"-m mark ! --mark " __stringify(SOCCR_MARK) " --source %s --sport %d --destination %s --dport %d -j DROP"

static char iptable_cmd_ipv4[] = "iptables";
static char iptable_cmd_ipv6[] = "ip6tables";

void preload_netfilter_modules(void)
{
	int fd = -1;

	/* same as socket modules, ip_tables and ip6_tables will be loaded by
	 * CRIU, so we should try and preload these as well.
	 */
	fd = open("/dev/null", O_RDWR);
	if (fd < 0) {
		fd = -1;
		pr_perror("failed to open /dev/null, using log fd for net module preload");
	}
	cr_system(fd, fd, fd, iptable_cmd_ipv4, (char *[]){ iptable_cmd_ipv4, "-L", "-n", NULL }, 0);
	cr_system(fd, fd, fd, iptable_cmd_ipv6, (char *[]){ iptable_cmd_ipv6, "-L", "-n", NULL }, 0);
	close_safe(&fd);
}

/* IPv4-Mapped IPv6 Addresses */
static int ipv6_addr_mapped(u32 *addr)
{
	return (addr[2] == htonl(0x0000ffff));
}

static int iptables_connection_switch_raw(int family, u32 *src_addr, u16 src_port, u32 *dst_addr, u16 dst_port,
					  bool input, bool lock)
{
	char sip[INET_ADDR_LEN], dip[INET_ADDR_LEN];
	char *cmd;
	char *argv[4] = { "sh", "-c", buf, NULL };
	int ret;

	if (family == AF_INET6 && ipv6_addr_mapped(dst_addr)) {
		family = AF_INET;
		src_addr = &src_addr[3];
		dst_addr = &dst_addr[3];
	}

	switch (family) {
	case AF_INET:
		cmd = iptable_cmd_ipv4;
		break;
	case AF_INET6:
		cmd = iptable_cmd_ipv6;
		break;
	default:
		pr_err("Unknown socket family %d\n", family);
		return -1;
	};

	if (!inet_ntop(family, (void *)src_addr, sip, INET_ADDR_LEN) ||
	    !inet_ntop(family, (void *)dst_addr, dip, INET_ADDR_LEN)) {
		pr_perror("nf: Can't translate ip addr");
		return -1;
	}

	snprintf(buf, sizeof(buf), IPTABLES_CONN_CMD, cmd, kdat.has_xtlocks ? "-w" : "", lock ? "-I" : "-D",
		 input ? "INPUT" : "OUTPUT", dip, (int)dst_port, sip, (int)src_port);

	pr_debug("\tRunning iptables [%s]\n", buf);

	/*
	 * cr_system is used here, because it blocks SIGCHLD before waiting
	 * a child and the child can't be waited from SIGCHLD handler.
	 */
	ret = cr_system(-1, -1, -1, "sh", argv, 0);
	if (ret < 0 || !WIFEXITED(ret) || WEXITSTATUS(ret)) {
		pr_err("Iptables configuration failed\n");
		return -1;
	}

	pr_info("%s %s:%d - %s:%d connection\n", lock ? "Locked" : "Unlocked", sip, (int)src_port, dip, (int)dst_port);
	return 0;
}

static int iptables_connection_switch(struct inet_sk_desc *sk, bool lock)
{
	int ret = 0;

	ret = iptables_connection_switch_raw(sk->sd.family, sk->src_addr, sk->src_port, sk->dst_addr, sk->dst_port,
					     true, lock);
	if (ret)
		return -1;

	ret = iptables_connection_switch_raw(sk->sd.family, sk->dst_addr, sk->dst_port, sk->src_addr, sk->src_port,
					     false, lock);
	if (ret) /* rollback */
		iptables_connection_switch_raw(sk->sd.family, sk->src_addr, sk->src_port, sk->dst_addr, sk->dst_port,
					       true, !lock);
	return ret;
}

int iptables_lock_connection(struct inet_sk_desc *sk)
{
	return iptables_connection_switch(sk, true);
}

int iptables_unlock_connection(struct inet_sk_desc *sk)
{
	return iptables_connection_switch(sk, false);
}

int iptables_unlock_connection_info(struct inet_sk_info *si)
{
	int ret = 0;

	ret |= iptables_connection_switch_raw(si->ie->family, si->ie->src_addr, si->ie->src_port, si->ie->dst_addr,
					      si->ie->dst_port, true, false);
	ret |= iptables_connection_switch_raw(si->ie->family, si->ie->dst_addr, si->ie->dst_port, si->ie->src_addr,
					      si->ie->src_port, false, false);
	/*
	 * rollback nothing in case of any error,
	 * because nobody checks errors of this function
	 */

	return ret;
}

int nftables_init_connection_lock(void)
{
#if defined(CONFIG_HAS_NFTABLES_LIB_API_0) || defined(CONFIG_HAS_NFTABLES_LIB_API_1)
	struct nft_ctx *nft;
	int ret = 0;

	nft = nft_ctx_new(NFT_CTX_DEFAULT);
	if (!nft)
		return -1;

	if (NFT_RUN_CMD(nft, "add table inet CRIU"))
		goto err2;

	if (NFT_RUN_CMD(nft, "add chain inet CRIU output { type filter hook output priority 0; }"))
		goto err1;

	if (NFT_RUN_CMD(nft, "add rule inet CRIU output meta mark " __stringify(SOCCR_MARK) " accept"))
		goto err1;

	if (NFT_RUN_CMD(nft, "add chain inet CRIU input { type filter hook input priority 0; }"))
		goto err1;

	if (NFT_RUN_CMD(nft, "add rule inet CRIU input meta mark " __stringify(SOCCR_MARK) " accept"))
		goto err1;

	/* IPv4 */
	if (NFT_RUN_CMD(nft, "add set inet CRIU conns4 { type ipv4_addr . inet_service . ipv4_addr . inet_service ; }"))
		goto err1;

	if (NFT_RUN_CMD(nft, "add rule inet CRIU output ip saddr . tcp sport . ip daddr . tcp dport @conns4 drop"))
		goto err1;

	if (NFT_RUN_CMD(nft, "add rule inet CRIU input ip saddr . tcp sport . ip daddr . tcp dport @conns4 drop"))
		goto err1;

	/* IPv6 */
	if (NFT_RUN_CMD(nft, "add set inet CRIU conns6 { type ipv6_addr . inet_service . ipv6_addr . inet_service ; }"))
		goto err1;

	if (NFT_RUN_CMD(nft, "add rule inet CRIU output ip6 saddr . tcp sport . ip6 daddr . tcp dport @conns6 drop"))
		goto err1;

	if (NFT_RUN_CMD(nft, "add rule inet CRIU input ip6 saddr . tcp sport . ip6 daddr . tcp dport @conns6 drop"))
		goto err1;

	goto out;

err1:
	NFT_RUN_CMD(nft, "delete table inet CRIU");
	pr_err("Locking network failed using nftables\n");
err2:
	ret = -1;
out:
	nft_ctx_free(nft);
	return ret;
#else
	pr_err("CRIU was built without libnftables support\n");
	return -1;
#endif
}

static int nftables_lock_connection_raw(int family, u32 *src_addr, u16 src_port, u32 *dst_addr, u16 dst_port)
{
#if defined(CONFIG_HAS_NFTABLES_LIB_API_0) || defined(CONFIG_HAS_NFTABLES_LIB_API_1)
	struct nft_ctx *nft;
	int ret = 0;
	char sip[INET_ADDR_LEN], dip[INET_ADDR_LEN];

	if (family == AF_INET6 && ipv6_addr_mapped(dst_addr)) {
		family = AF_INET;
		src_addr = &src_addr[3];
		dst_addr = &dst_addr[3];
	}

	if (!inet_ntop(family, (void *)src_addr, sip, INET_ADDR_LEN)) {
		pr_perror("nf: Can't convert src ip addr");
		return -1;
	}

	if (!inet_ntop(family, (void *)dst_addr, dip, INET_ADDR_LEN)) {
		pr_perror("nf: Can't convert dst ip addr");
		return -1;
	}

	nft = nft_ctx_new(NFT_CTX_DEFAULT);
	if (!nft)
		return -1;

	snprintf(buf, sizeof(buf), NFTABLES_CONN_CMD, family == AF_INET ? '4' : '6', dip, (int)dst_port, sip,
		 (int)src_port);

	pr_debug("\tRunning nftables [%s]\n", buf);

	if (NFT_RUN_CMD(nft, buf)) {
		ret = -1;
		pr_err("Locking connection failed using nftables\n");
	}

	nft_ctx_free(nft);
	return ret;
#else
	pr_err("CRIU was built without libnftables support\n");
	return -1;
#endif
}

int nftables_lock_connection(struct inet_sk_desc *sk)
{
	int ret = 0;

	ret = nftables_lock_connection_raw(sk->sd.family, sk->src_addr, sk->src_port, sk->dst_addr, sk->dst_port);
	if (ret)
		return -1;

	ret = nftables_lock_connection_raw(sk->sd.family, sk->dst_addr, sk->dst_port, sk->src_addr, sk->src_port);

	return ret;
}
