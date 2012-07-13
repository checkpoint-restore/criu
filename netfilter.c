#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <wait.h>
#include <stdlib.h>

#include "types.h"
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

static const char *nf_conn_cmd = "iptables -t filter %s INPUT --protocol tcp "
	"--source %s --sport %d --destination %s --dport %d -j DROP";

static int nf_connection_switch_raw(u32 *src_addr, u16 src_port, u32 *dst_addr, u16 dst_port, int lock)
{
	char sip[INET_ADDR_LEN], dip[INET_ADDR_LEN];
	int ret;

	if (!inet_ntop(PF_INET, (void *)src_addr, sip, INET_ADDR_LEN) ||
			!inet_ntop(PF_INET, (void *)dst_addr, dip, INET_ADDR_LEN)) {
		pr_perror("nf: Can't translate ip addr\n");
		return -1;
	}

	snprintf(buf, sizeof(buf), nf_conn_cmd, lock ? "-A" : "-D",
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
	if (sk->sd.family != PF_INET) {
		pr_err("nf: Only IPv4 for now\n");
		return -1;
	}

	return nf_connection_switch_raw(sk->src_addr, sk->src_port,
			sk->dst_addr, sk->dst_port, lock);
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
	return nf_connection_switch_raw(si->ie->src_addr, si->ie->src_port,
			si->ie->dst_addr, si->ie->dst_port, 0);
}
