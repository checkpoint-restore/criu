#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <wait.h>
#include <stdlib.h>

#include "asm/types.h"
#include "util.h"
#include "list.h"
#include "files.h"
#include "netfilter.h"
#include "sockets.h"
#include "sk-inet.h"

static char buf[512];

/*
 * Need to configure simple netfilter rules for blocking connections
 * ANy brave soul to write it using xtables-devel?
 */

static const char *nf_conn_cmd = "%s -t filter %s INPUT --protocol tcp "
	"--source %s --sport %d --destination %s --dport %d -j DROP";

static char iptable_cmd_ipv4[] = "iptables";
static char iptable_cmd_ipv6[] = "ip6tables";

static int nf_connection_switch_raw(int family, u32 *src_addr, u16 src_port, u32 *dst_addr, u16 dst_port, int lock)
{
	char sip[INET_ADDR_LEN], dip[INET_ADDR_LEN];
	char *cmd;
	int ret;

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

	snprintf(buf, sizeof(buf), nf_conn_cmd, cmd, lock ? "-A" : "-D",
			dip, (int)dst_port, sip, (int)src_port);

	pr_debug("\tRunning iptables [%s]\n", buf);
	ret = system(buf);
	if (ret < 0 || !WIFEXITED(ret) || WEXITSTATUS(ret)) {
		pr_perror("Iptables configuration failed");
		return -1;
	}

	pr_info("%s %s:%d - %s:%d connection\n", lock ? "Locked" : "Unlocked",
			sip, (int)src_port, dip, (int)dst_port);
	return 0;
}

static int nf_connection_switch(struct inet_sk_desc *sk, int lock)
{
	int ret = 0;

	ret = nf_connection_switch_raw(sk->sd.family,
			sk->src_addr, sk->src_port,
			sk->dst_addr, sk->dst_port, lock);
	if (ret)
		return -1;

	ret = nf_connection_switch_raw(sk->sd.family,
			sk->dst_addr, sk->dst_port,
			sk->src_addr, sk->src_port, lock);
	if (ret) /* rollback */
		nf_connection_switch_raw(sk->sd.family,
			sk->src_addr, sk->src_port,
			sk->dst_addr, sk->dst_port, !lock);
	return ret;
}

int nf_lock_connection(struct inet_sk_desc *sk)
{
	return nf_connection_switch(sk, 1);
}

int nf_unlock_connection(struct inet_sk_desc *sk)
{
	return nf_connection_switch(sk, 0);
}

int nf_unlock_connection_info(struct inet_sk_info *si)
{
	int ret = 0;

	ret |= nf_connection_switch_raw(si->ie->family,
			si->ie->src_addr, si->ie->src_port,
			si->ie->dst_addr, si->ie->dst_port, 0);
	ret |= nf_connection_switch_raw(si->ie->family,
			si->ie->dst_addr, si->ie->dst_port,
			si->ie->src_addr, si->ie->src_port, 0);
	/*
	 * rollback nothing in case of any error,
	 * because nobody checks errors of this function
	 */

	return ret;
}
