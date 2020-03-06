#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include <string.h>
#include <net/if_arp.h>
#include <sys/wait.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <libnl3/netlink/attr.h>
#include <libnl3/netlink/msg.h>
#include <libnl3/netlink/netlink.h>

#if defined(CONFIG_HAS_NFTABLES_LIB_API_0) || defined(CONFIG_HAS_NFTABLES_LIB_API_1)
#include <nftables/libnftables.h>
#endif

#ifdef CONFIG_HAS_SELINUX
#include <selinux/selinux.h>
#endif

#include "../soccr/soccr.h"

#include "imgset.h"
#include "namespaces.h"
#include "net.h"
#include "libnetlink.h"
#include "cr_options.h"
#include "sk-inet.h"
#include "tun.h"
#include "util-pie.h"
#include "plugin.h"
#include "action-scripts.h"
#include "sockets.h"
#include "pstree.h"
#include "string.h"
#include "sysctl.h"
#include "kerndat.h"
#include "util.h"
#include "external.h"
#include "fdstore.h"

#include "protobuf.h"
#include "images/netdev.pb-c.h"
#include "images/inventory.pb-c.h"

#ifndef IFLA_LINK_NETNSID
#define IFLA_LINK_NETNSID	37
#undef IFLA_MAX
#define IFLA_MAX IFLA_LINK_NETNSID
#endif

#ifndef RTM_NEWNSID
#define RTM_NEWNSID		88
#endif

#ifndef IFLA_MACVLAN_FLAGS
#define IFLA_MACVLAN_FLAGS 2
#endif

enum {
	IFLA_IPTUN_UNSPEC,
	IFLA_IPTUN_LINK,
	IFLA_IPTUN_LOCAL,
	IFLA_IPTUN_REMOTE,
	IFLA_IPTUN_TTL,
	IFLA_IPTUN_TOS,
	IFLA_IPTUN_ENCAP_LIMIT,
	IFLA_IPTUN_FLOWINFO,
	IFLA_IPTUN_FLAGS,
	IFLA_IPTUN_PROTO,
	IFLA_IPTUN_PMTUDISC,
	IFLA_IPTUN_6RD_PREFIX,
	IFLA_IPTUN_6RD_RELAY_PREFIX,
	IFLA_IPTUN_6RD_PREFIXLEN,
	IFLA_IPTUN_6RD_RELAY_PREFIXLEN,
	IFLA_IPTUN_ENCAP_TYPE,
	IFLA_IPTUN_ENCAP_FLAGS,
	IFLA_IPTUN_ENCAP_SPORT,
	IFLA_IPTUN_ENCAP_DPORT,
	__IFLA_IPTUN_MAX,
};
#define IFLA_IPTUN_MAX  (__IFLA_IPTUN_MAX - 1)

static int ns_sysfs_fd = -1;

int read_ns_sys_file(char *path, char *buf, int len)
{
	int fd, rlen;

	BUG_ON(ns_sysfs_fd == -1);

	fd = openat(ns_sysfs_fd, path, O_RDONLY, 0);
	if (fd < 0) {
		pr_perror("Can't open ns' %s", path);
		return -1;
	}

	rlen = read(fd, buf, len);
	close(fd);

	if (rlen == len) {
		pr_err("Too small buffer to read ns sys file %s\n", path);
		return -1;
	}

	if (rlen > 0)
		buf[rlen - 1] = '\0';

	return rlen;
}

static bool sysctl_entries_equal(SysctlEntry *a, SysctlEntry *b)
{
	if (a->type != b->type)
		return false;

	switch (a->type) {
		case SYSCTL_TYPE__CTL_32:
			return a->has_iarg && b->has_iarg && a->iarg == b->iarg;
		case SYSCTL_TYPE__CTL_STR:
			return a->sarg && b->sarg && !strcmp(a->sarg, b->sarg);
		default:;
	}

	return false;
}

static char *devconfs4[] = {
	"accept_local",
	"accept_redirects",
	"accept_source_route",
	"arp_accept",
	"arp_announce",
	"arp_filter",
	"arp_ignore",
	"arp_notify",
	"bootp_relay",
	"disable_policy",
	"disable_xfrm",
	"force_igmp_version",
	"forwarding",
	"igmpv2_unsolicited_report_interval",
	"igmpv3_unsolicited_report_interval",
	"log_martians",
	"medium_id",
	"promote_secondaries",
	"proxy_arp",
	"proxy_arp_pvlan",
	"route_localnet",
	"rp_filter",
	"secure_redirects",
	"send_redirects",
	"shared_media",
	"src_valid_mark",
	"tag",
	"ignore_routes_with_linkdown",
	"drop_gratuitous_arp",
	"drop_unicast_in_l2_multicast",
};

char *devconfs6[] = {
	"accept_dad",
	"accept_ra",
	"accept_ra_defrtr",
	"accept_ra_from_local",
	"accept_ra_min_hop_limit",
	"accept_ra_mtu",
	"accept_ra_pinfo",
	"accept_ra_rt_info_max_plen",
	"accept_ra_rtr_pref",
	"accept_redirects",
	"accept_source_route",
	"autoconf",
	"dad_transmits",
	"disable_ipv6",
	"drop_unicast_in_l2_multicast",
	"drop_unsolicited_na",
	"force_mld_version",
	"force_tllao",
	"forwarding",
	"hop_limit",
	"ignore_routes_with_linkdown",
	"keep_addr_on_down",
	"max_addresses",
	"max_desync_factor",
	"mldv1_unsolicited_report_interval",
	"mldv2_unsolicited_report_interval",
	"mtu",
	"ndisc_notify",
	"optimistic_dad",
	"proxy_ndp",
	"regen_max_retry",
	"router_probe_interval",
	"router_solicitation_delay",
	"router_solicitation_interval",
	"router_solicitations",
	"stable_secret",
	"suppress_frag_ndisc",
	"temp_prefered_lft",
	"temp_valid_lft",
	"use_oif_addrs_only",
	"use_optimistic",
	"use_tempaddr",
};

#define CONF_OPT_PATH "net/%s/conf/%s/%s"
#define MAX_CONF_OPT_PATH IFNAMSIZ+60
#define MAX_STR_CONF_LEN 200

static const char *unix_conf_entries[] = {
	"max_dgram_qlen",
};

/*
 * MAX_CONF_UNIX_PATH = (sizeof(CONF_UNIX_FMT) - strlen("%s"))
 * 					  + MAX_CONF_UNIX_OPT_PATH
 */
#define CONF_UNIX_BASE		"net/unix"
#define CONF_UNIX_FMT		CONF_UNIX_BASE"/%s"
#define MAX_CONF_UNIX_OPT_PATH	32
#define MAX_CONF_UNIX_PATH	(sizeof(CONF_UNIX_FMT) + MAX_CONF_UNIX_OPT_PATH - 2)

static int net_conf_op(char *tgt, SysctlEntry **conf, int n, int op, char *proto,
		struct sysctl_req *req, char (*path)[MAX_CONF_OPT_PATH], int size,
		char **devconfs, SysctlEntry **def_conf)
{
	int i, ri, ar = -1;
	int ret, flags = op == CTL_READ ? CTL_FLAGS_OPTIONAL : 0;
	SysctlEntry **rconf;

	if (n > size)
		pr_warn("The image contains unknown sysctl-s\n");

	if (opts.weak_sysctls)
		flags = CTL_FLAGS_OPTIONAL;

	rconf = xmalloc(sizeof(SysctlEntry *) * size);
	if (!rconf)
		return -1;

	for (i = 0, ri = 0; i < size; i++) {
		if (i >= n) {
			pr_warn("Skip %s/%s\n", tgt, devconfs[i]);
			continue;
		}
		/*
		 * If dev conf value is the same as default skip restoring it,
		 * mtu may be changed by disable_ipv6 so we can not skip
		 * it's restore
		 */
		if (def_conf && sysctl_entries_equal(conf[i], def_conf[i])
				&& strcmp(devconfs[i], "mtu")) {
			pr_debug("Skip %s/%s, coincides with default\n", tgt, devconfs[i]);
			continue;
		}

		/*
		 * Make "accept_redirects" go last on write(it should
		 * restore after forwarding to be correct)
		 */
		if (op == CTL_WRITE && !strcmp(devconfs[i], "accept_redirects")) {
			ar = i;
			continue;
		}

		snprintf(path[i], MAX_CONF_OPT_PATH, CONF_OPT_PATH, proto, tgt, devconfs[i]);
		req[ri].name = path[i];
		req[ri].flags = flags;
		switch (conf[i]->type) {
			case SYSCTL_TYPE__CTL_32:
				req[ri].type = CTL_32;

				/* skip non-existing sysctl */
				if (op == CTL_WRITE && !conf[i]->has_iarg)
					continue;

				req[ri].arg = &conf[i]->iarg;
				break;
			case SYSCTL_TYPE__CTL_STR:
				req[ri].type = CTL_STR(MAX_STR_CONF_LEN);
				req[ri].flags |= op == CTL_READ && !strcmp(devconfs[i], "stable_secret")
					? CTL_FLAGS_READ_EIO_SKIP : 0;

				/* skip non-existing sysctl */
				if (op == CTL_WRITE && !conf[i]->sarg)
					continue;

				req[ri].arg = conf[i]->sarg;
				break;
			default:
				continue;
		}
		rconf[ri] = conf[i];
		ri++;
	}

	if (ar != -1
	    && conf[ar]->type == SYSCTL_TYPE__CTL_32
	    && conf[ar]->has_iarg) {
		snprintf(path[ar], MAX_CONF_OPT_PATH, CONF_OPT_PATH, proto, tgt, devconfs[ar]);
		req[ri].name = path[ar];
		req[ri].type = CTL_32;
		req[ri].arg = &conf[ar]->iarg;
		req[ri].flags = flags;
		rconf[ri] = conf[ar];
		ri++;
	}

	ret = sysctl_op(req, ri, op, CLONE_NEWNET);
	if (ret < 0) {
		pr_err("Failed to %s %s/<confs>\n", (op == CTL_READ)?"read":"write", tgt);
		goto err_free;
	}

	if (op == CTL_READ) {
		/* (un)mark (non-)existing sysctls in image */
		for (i = 0; i < ri; i++)
			if (req[i].flags & CTL_FLAGS_HAS) {
				if (rconf[i]->type == SYSCTL_TYPE__CTL_32)
					rconf[i]->has_iarg = true;
			} else {
				if (rconf[i]->type == SYSCTL_TYPE__CTL_STR)
					rconf[i]->sarg = NULL;
			}
	}

err_free:
	xfree(rconf);
	return ret;
}

static int ipv4_conf_op(char *tgt, SysctlEntry **conf, int n, int op, SysctlEntry **def_conf)
{
	struct sysctl_req req[ARRAY_SIZE(devconfs4)];
	char path[ARRAY_SIZE(devconfs4)][MAX_CONF_OPT_PATH];

	return net_conf_op(tgt, conf, n, op, "ipv4",
			req, path, ARRAY_SIZE(devconfs4),
			devconfs4, def_conf);
}

static int ipv6_conf_op(char *tgt, SysctlEntry **conf, int n, int op, SysctlEntry **def_conf)
{
	struct sysctl_req req[ARRAY_SIZE(devconfs6)];
	char path[ARRAY_SIZE(devconfs6)][MAX_CONF_OPT_PATH];

	return net_conf_op(tgt, conf, n, op, "ipv6",
			req, path, ARRAY_SIZE(devconfs6),
			devconfs6, def_conf);
}

static int unix_conf_op(SysctlEntry ***rconf, size_t *n, int op)
{
	int i, ret = -1, flags = 0;
	char path[ARRAY_SIZE(unix_conf_entries)][MAX_CONF_UNIX_PATH] = { };
	struct sysctl_req req[ARRAY_SIZE(unix_conf_entries)] = { };
	SysctlEntry **conf = *rconf;

	if (*n != ARRAY_SIZE(unix_conf_entries)) {
		pr_err("unix: Unexpected entries in config (%zu %zu)\n",
			*n, ARRAY_SIZE(unix_conf_entries));
		return -EINVAL;
	}

	if (opts.weak_sysctls || op == CTL_READ)
		flags = CTL_FLAGS_OPTIONAL;

	for (i = 0; i < *n; i++) {
		snprintf(path[i], MAX_CONF_UNIX_PATH, CONF_UNIX_FMT,
			unix_conf_entries[i]);
		req[i].name = path[i];
		req[i].flags = flags;

		switch (conf[i]->type) {
		case SYSCTL_TYPE__CTL_32:
			req[i].type = CTL_32;
			req[i].arg = &conf[i]->iarg;
			break;
		default:
			pr_err("unix: Unknown config type %d\n",
				conf[i]->type);
			return -1;
		}
	}

	ret = sysctl_op(req, *n, op, CLONE_NEWNET);
	if (ret < 0) {
		pr_err("unix: Failed to %s %s/<confs>\n",
			(op == CTL_READ) ? "read" : "write",
			CONF_UNIX_BASE);
		return -1;
	}

	if (op == CTL_READ) {
		bool has_entries = false;

		for (i = 0; i < *n; i++) {
			if (req[i].flags & CTL_FLAGS_HAS) {
				conf[i]->has_iarg = true;
				if (!has_entries)
					has_entries = true;
			}
		}

		/*
		 * Zap the whole section of data.
		 * Unix conf is optional.
		 */
		if (!has_entries) {
			*n = 0;
			*rconf = NULL;
		}
	}

	return 0;
}

/*
 * I case if some entry is missing in
 * the kernel, simply write DEVCONFS_UNUSED
 * into the image so we would skip it.
 */
#define DEVCONFS_UNUSED		(-1u)

static int ipv4_conf_op_old(char *tgt, int *conf, int n, int op, int *def_conf)
{
	int i, ri;
	int ret, flags = op == CTL_READ ? CTL_FLAGS_OPTIONAL : 0;
	struct sysctl_req req[ARRAY_SIZE(devconfs4)];
	char path[ARRAY_SIZE(devconfs4)][MAX_CONF_OPT_PATH];

	if (n > ARRAY_SIZE(devconfs4))
		pr_warn("The image contains unknown sysctl-s\n");

	for (i = 0, ri = 0; i < ARRAY_SIZE(devconfs4); i++) {
		if (i >= n) {
			pr_warn("Skip %s/%s\n", tgt, devconfs4[i]);
			continue;
		}
		/*
		 * If dev conf value is the same as default skip restoring it
		 */
		if (def_conf && conf[i] == def_conf[i]) {
			pr_debug("DEBUG Skip %s/%s, val =%d\n", tgt, devconfs4[i], conf[i]);
			continue;
		}

		if (op == CTL_WRITE && conf[i] == DEVCONFS_UNUSED)
			continue;
		else if (op == CTL_READ)
			conf[i] = DEVCONFS_UNUSED;

		snprintf(path[i], MAX_CONF_OPT_PATH, CONF_OPT_PATH, "ipv4", tgt, devconfs4[i]);
		req[ri].name = path[i];
		req[ri].arg = &conf[i];
		req[ri].type = CTL_32;
		req[ri].flags = flags;
		ri++;
	}

	ret = sysctl_op(req, ri, op, CLONE_NEWNET);
	if (ret < 0) {
		pr_err("Failed to %s %s/<confs>\n", (op == CTL_READ)?"read":"write", tgt);
		return -1;
	}
	return 0;
}

int write_netdev_img(NetDeviceEntry *nde, struct cr_imgset *fds, struct nlattr **info)
{
	return pb_write_one(img_from_set(fds, CR_FD_NETDEV), nde, PB_NETDEV);
}

static int lookup_net_by_netid(struct ns_id *ns, int net_id)
{
	struct netns_id *p;

	list_for_each_entry(p, &ns->net.ids, node)
		if (p->netnsid_value == net_id)
			return p->target_ns_id;

	return -1;
}

static int dump_one_netdev(int type, struct ifinfomsg *ifi,
		struct nlattr **tb, struct ns_id *ns, struct cr_imgset *fds,
		int (*dump)(NetDeviceEntry *, struct cr_imgset *, struct nlattr **info))
{
	int ret = -1, i, peer_ifindex;
	NetDeviceEntry netdev = NET_DEVICE_ENTRY__INIT;
	SysctlEntry *confs4 = NULL;
	int size4 = ARRAY_SIZE(devconfs4);
	SysctlEntry *confs6 = NULL;
	int size6 = ARRAY_SIZE(devconfs6);
	char stable_secret[MAX_STR_CONF_LEN + 1] = {};
	struct nlattr *info[IFLA_INFO_MAX + 1], **arg = NULL;

	if (!tb[IFLA_IFNAME]) {
		pr_err("No name for link %d\n", ifi->ifi_index);
		return -1;
	}

	netdev.type = type;
	netdev.ifindex = ifi->ifi_index;
	netdev.mtu = *(int *)RTA_DATA(tb[IFLA_MTU]);
	netdev.flags = ifi->ifi_flags;
	netdev.name = RTA_DATA(tb[IFLA_IFNAME]);

	if (kdat.has_nsid) {
		s32 nsid = -1;

		peer_ifindex = ifi->ifi_index;
		if (tb[IFLA_LINK])
			peer_ifindex = nla_get_u32(tb[IFLA_LINK]);

		netdev.has_peer_ifindex = true;
		netdev.peer_ifindex = peer_ifindex;

		if (tb[IFLA_LINK_NETNSID])
			nsid = nla_get_s32(tb[IFLA_LINK_NETNSID]);

		pr_debug("The peer link is in the %d netns with the %u index\n",
						nsid, netdev.peer_ifindex);

		if (nsid == -1)
			nsid = ns->id;
		else
			nsid = lookup_net_by_netid(ns, nsid);
		if (nsid < 0) {
			pr_warn("The %s veth is in an external netns\n",
								netdev.name);
		} else {
			netdev.has_peer_nsid = true;
			netdev.peer_nsid = nsid;
		}
	}
	/*
	 * If kdat.has_nsid is false, a multiple network namespaces are not dumped,
	 * so if we are here, this means only one netns is dumped.
	 */

	if (tb[IFLA_ADDRESS] && (type != ND_TYPE__LOOPBACK)) {
		netdev.has_address = true;
		netdev.address.data = nla_data(tb[IFLA_ADDRESS]);
		netdev.address.len = nla_len(tb[IFLA_ADDRESS]);
		pr_info("Found ll addr (%02x:../%d) for %s\n",
				(int)netdev.address.data[0],
				(int)netdev.address.len, netdev.name);
	}

	if (tb[IFLA_MASTER]) {
		netdev.has_master = true;
		netdev.master = nla_get_u32(tb[IFLA_MASTER]);
	}

	netdev.n_conf4 = size4;
	netdev.conf4 = xmalloc(sizeof(SysctlEntry *) * size4);
	if (!netdev.conf4)
		goto err_free;

	confs4 = xmalloc(sizeof(SysctlEntry) * size4);
	if (!confs4)
		goto err_free;

	for (i = 0; i < size4; i++) {
		sysctl_entry__init(&confs4[i]);
		netdev.conf4[i] = &confs4[i];
		netdev.conf4[i]->type = CTL_32;
	}

	netdev.n_conf6 = size6;
	netdev.conf6 = xmalloc(sizeof(SysctlEntry *) * size6);
	if (!netdev.conf6)
		goto err_free;

	confs6 = xmalloc(sizeof(SysctlEntry) * size6);
	if (!confs6)
		goto err_free;

	for (i = 0; i < size6; i++) {
		sysctl_entry__init(&confs6[i]);
		netdev.conf6[i] = &confs6[i];
		if (strcmp(devconfs6[i], "stable_secret")) {
			netdev.conf6[i]->type = SYSCTL_TYPE__CTL_32;
		} else {
			netdev.conf6[i]->type = SYSCTL_TYPE__CTL_STR;
			netdev.conf6[i]->sarg = stable_secret;
		}
	}

	ret = ipv4_conf_op(netdev.name, netdev.conf4, size4, CTL_READ, NULL);
	if (ret < 0)
		goto err_free;

	ret = ipv6_conf_op(netdev.name, netdev.conf6, size6, CTL_READ, NULL);
	if (ret < 0)
		goto err_free;

	if (!dump)
		dump = write_netdev_img;

	if (tb[IFLA_LINKINFO]) {
		ret = nla_parse_nested(info, IFLA_INFO_MAX, tb[IFLA_LINKINFO], NULL);
		if (ret < 0) {
			pr_err("failed to parse nested linkinfo\n");
			return -1;
		}
		arg = info;
	}

	ret = dump(&netdev, fds, arg);
err_free:
	xfree(netdev.conf4);
	xfree(confs4);
	xfree(netdev.conf6);
	xfree(confs6);
	return ret;
}

static char *link_kind(struct ifinfomsg *ifi, struct nlattr **tb)
{
	struct nlattr *linkinfo[IFLA_INFO_MAX + 1];

	if (!tb[IFLA_LINKINFO]) {
		pr_err("No linkinfo for eth link %d\n", ifi->ifi_index);
		return NULL;
	}

	nla_parse_nested(linkinfo, IFLA_INFO_MAX, tb[IFLA_LINKINFO], NULL);
	if (!linkinfo[IFLA_INFO_KIND]) {
		pr_err("No kind for eth link %d\n", ifi->ifi_index);
		return NULL;
	}

	return nla_data(linkinfo[IFLA_INFO_KIND]);
}

static int dump_unknown_device(struct ifinfomsg *ifi, char *kind,
		struct nlattr **tb, struct ns_id *ns, struct cr_imgset *fds)
{
	int ret;

	ret = run_plugins(DUMP_EXT_LINK, ifi->ifi_index, ifi->ifi_type, kind);
	if (ret == 0)
		return dump_one_netdev(ND_TYPE__EXTLINK, ifi, tb, ns, fds, NULL);

	if (ret == -ENOTSUP)
		pr_err("Unsupported link %d (type %d kind %s)\n",
				ifi->ifi_index, ifi->ifi_type, kind);
	return -1;
}

static int dump_bridge(NetDeviceEntry *nde, struct cr_imgset *imgset, struct nlattr **info)
{
	return write_netdev_img(nde, imgset, info);
}

static int dump_macvlan(NetDeviceEntry *nde, struct cr_imgset *imgset, struct nlattr **info)
{
	MacvlanLinkEntry macvlan = MACVLAN_LINK_ENTRY__INIT;
	int ret;
	struct nlattr *data[IFLA_MACVLAN_FLAGS+1];

	if (!info || !info[IFLA_INFO_DATA]) {
		pr_err("no data for macvlan\n");
		return -1;
	}

	ret = nla_parse_nested(data, IFLA_MACVLAN_FLAGS, info[IFLA_INFO_DATA], NULL);
	if (ret < 0) {
		pr_err("failed ot parse macvlan data\n");
		return -1;
	}

	if (!data[IFLA_MACVLAN_MODE]) {
		pr_err("macvlan mode required for %s\n", nde->name);
		return -1;
	}

	macvlan.mode = *((u32 *)RTA_DATA(data[IFLA_MACVLAN_MODE]));

	if (data[IFLA_MACVLAN_FLAGS])
		macvlan.flags = *((u16 *) RTA_DATA(data[IFLA_MACVLAN_FLAGS]));

	nde->macvlan = &macvlan;
	return write_netdev_img(nde, imgset, info);
}

static int dump_one_ethernet(struct ifinfomsg *ifi, char *kind,
		struct nlattr **tb, struct ns_id *ns, struct cr_imgset *fds)
{
	if (!strcmp(kind, "veth"))
		/*
		 * This is not correct. The peer of the veth device may
		 * be either outside or inside the netns we're working
		 * on, but there's currently no way of finding this out.
		 *
		 * Sigh... we have to assume, that the veth device is a
		 * connection to the outer world and just dump this end :(
		 */
		return dump_one_netdev(ND_TYPE__VETH, ifi, tb, ns, fds, NULL);
	if (!strcmp(kind, "tun"))
		return dump_one_netdev(ND_TYPE__TUN, ifi, tb, ns, fds, dump_tun_link);
	if (!strcmp(kind, "bridge"))
		return dump_one_netdev(ND_TYPE__BRIDGE, ifi, tb, ns, fds, dump_bridge);
	if (!strcmp(kind, "gretap")) {
		char *name = (char *)RTA_DATA(tb[IFLA_IFNAME]);

		if (!name) {
			pr_err("gretap %d has no name\n", ifi->ifi_index);
			return -1;
		}

		if (!strcmp(name, "gretap0")) {
			pr_info("found %s, ignoring\n", name);
			return 0;
		}

		pr_warn("GRE tap device %s not supported natively\n", name);
	}
	if (!strcmp(kind, "macvlan"))
		return dump_one_netdev(ND_TYPE__MACVLAN, ifi, tb, ns, fds, dump_macvlan);

	return dump_unknown_device(ifi, kind, tb, ns, fds);
}

static int dump_one_gendev(struct ifinfomsg *ifi, char *kind,
		struct nlattr **tb, struct ns_id *ns, struct cr_imgset *fds)
{
	if (!strcmp(kind, "tun"))
		return dump_one_netdev(ND_TYPE__TUN, ifi, tb, ns, fds, dump_tun_link);

	return dump_unknown_device(ifi, kind, tb, ns, fds);
}

static int dump_one_voiddev(struct ifinfomsg *ifi, char *kind,
		struct nlattr **tb, struct ns_id *ns, struct cr_imgset *fds)
{
	if (!strcmp(kind, "venet"))
		return dump_one_netdev(ND_TYPE__VENET, ifi, tb, ns, fds, NULL);

	return dump_unknown_device(ifi, kind, tb, ns, fds);
}

static int dump_one_gre(struct ifinfomsg *ifi, char *kind,
		struct nlattr **tb, struct ns_id *ns, struct cr_imgset *fds)
{
	if (!strcmp(kind, "gre")) {
		char *name = (char *)RTA_DATA(tb[IFLA_IFNAME]);
		if (!name) {
			pr_err("gre device %d has no name\n", ifi->ifi_index);
			return -1;
		}

		if (!strcmp(name, "gre0")) {
			pr_info("found %s, ignoring\n", name);
			return 0;
		}

		pr_warn("GRE tunnel device %s not supported natively\n", name);
	}

	return dump_unknown_device(ifi, kind, tb, ns, fds);
}

static int dump_sit(NetDeviceEntry *nde, struct cr_imgset *imgset, struct nlattr **info)
{
	int ret;
	struct nlattr *data[__IFLA_IPTUN_MAX];
	SitEntry se = SIT_ENTRY__INIT;
	/* There are for IP(v6) addresses kernel feeds to us */
	uint32_t a_local, a_remote, rd_prefix[4], rl_prefix;

	if (!info || !info[IFLA_INFO_DATA]) {
		pr_err("no data for sit\n");
		return -1;
	}

	pr_info("Some data for SIT provided\n");
	ret = nla_parse_nested(data, IFLA_IPTUN_MAX, info[IFLA_INFO_DATA], NULL);
	if (ret < 0) {
		pr_err("failed ot parse sit data\n");
		return -1;
	}

#define ENCODE_ENTRY(__type, __ifla, __proto)	do {			\
		if (data[__ifla]) {					\
			se.__proto = *(__type *)nla_data(data[__ifla]);	\
			se.has_##__proto = true;			\
		}							\
	} while (0)

	if (data[IFLA_IPTUN_LOCAL]) {
		a_local = *(u32 *)nla_data(data[IFLA_IPTUN_LOCAL]);
		if (a_local != 0) {
			se.n_local = 1;
			se.local = &a_local;
		}
	}

	if (data[IFLA_IPTUN_REMOTE]) {
		a_remote = *(u32 *)nla_data(data[IFLA_IPTUN_REMOTE]);
		if (a_remote != 0) {
			se.n_remote = 1;
			se.remote = &a_remote;
		}
	}

	ENCODE_ENTRY(u32, IFLA_IPTUN_LINK,  link);
	ENCODE_ENTRY(u8,  IFLA_IPTUN_TTL,   ttl);
	ENCODE_ENTRY(u8,  IFLA_IPTUN_TOS,   tos);
	ENCODE_ENTRY(u16, IFLA_IPTUN_FLAGS, flags);
	ENCODE_ENTRY(u8,  IFLA_IPTUN_PROTO, proto);

	if (data[IFLA_IPTUN_PMTUDISC]) {
		u8 v;

		v = *(u8 *)nla_data(data[IFLA_IPTUN_PMTUDISC]);
		if (v)
			se.pmtudisc = se.has_pmtudisc = true;
	}

	ENCODE_ENTRY(u16, IFLA_IPTUN_ENCAP_TYPE,  encap_type);
	ENCODE_ENTRY(u16, IFLA_IPTUN_ENCAP_FLAGS, encap_flags);
	ENCODE_ENTRY(u16, IFLA_IPTUN_ENCAP_SPORT, encap_sport);
	ENCODE_ENTRY(u16, IFLA_IPTUN_ENCAP_DPORT, encap_dport);

	if (data[IFLA_IPTUN_6RD_PREFIXLEN]) {
		se.rd_prefixlen = *(u16 *)nla_data(data[IFLA_IPTUN_6RD_PREFIXLEN]);
		if (!se.rd_prefixlen)
			goto skip;

		if (!data[IFLA_IPTUN_6RD_PREFIX]) {
			pr_err("No 6rd prefix for sit device\n");
			return -1;
		}

		se.has_rd_prefixlen = true;
		memcpy(&rd_prefix, nla_data(data[IFLA_IPTUN_6RD_PREFIX]), sizeof(rd_prefix));
		se.n_rd_prefix = 4;
		se.rd_prefix = rd_prefix;

		se.relay_prefixlen = *(u16 *)nla_data(data[IFLA_IPTUN_6RD_RELAY_PREFIXLEN]);
		if (!se.relay_prefixlen)
			goto skip;

		if (!data[IFLA_IPTUN_6RD_RELAY_PREFIX]) {
			pr_err("No 6rd relay prefix for sit device\n");
			return -1;
		}

		se.has_relay_prefixlen = true;
		memcpy(&rl_prefix, nla_data(data[IFLA_IPTUN_6RD_RELAY_PREFIX]), sizeof(rl_prefix));
		se.n_relay_prefix = 1;
		se.relay_prefix = &rl_prefix;
skip:;
	}

#undef ENCODE_ENTRY

	nde->sit = &se;
	return write_netdev_img(nde, imgset, info);
}

static int dump_one_sit(struct ifinfomsg *ifi, char *kind,
		struct nlattr **tb, struct ns_id *ns, struct cr_imgset *fds)
{
	char *name;

	if (strcmp(kind, "sit")) {
		pr_err("SIT device with %s kind\n", kind);
		return -1;
	}

	name = (char *)RTA_DATA(tb[IFLA_IFNAME]);
	if (!name) {
		pr_err("sit device %d has no name\n", ifi->ifi_index);
		return -1;
	}

	if (!strcmp(name, "sit0")) {
		pr_info("found %s, ignoring\n", name);
		return 0;
	}

	return dump_one_netdev(ND_TYPE__SIT, ifi, tb, ns, fds, dump_sit);
}

static int list_one_link(struct nlmsghdr *hdr, struct ns_id *ns, void *arg)
{
	return 0;
}

static int dump_one_link(struct nlmsghdr *hdr, struct ns_id *ns, void *arg)
{
	struct cr_imgset *fds = arg;
	struct ifinfomsg *ifi;
	int ret = 0, len = hdr->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
	struct nlattr *tb[IFLA_MAX + 1];
	char *kind;

	ifi = NLMSG_DATA(hdr);

	if (len < 0) {
		pr_err("No iflas for link %d\n", ifi->ifi_index);
		return -1;
	}

	nlmsg_parse(hdr, sizeof(struct ifinfomsg), tb, IFLA_MAX, NULL);
	pr_info("\tLD: Got link %d, type %d\n", ifi->ifi_index, ifi->ifi_type);

	if (ifi->ifi_type == ARPHRD_LOOPBACK)
		return dump_one_netdev(ND_TYPE__LOOPBACK, ifi, tb, ns, fds, NULL);

	kind = link_kind(ifi, tb);
	if (!kind)
		goto unk;

	switch (ifi->ifi_type) {
	case ARPHRD_ETHER:
		ret = dump_one_ethernet(ifi, kind, tb, ns, fds);
		break;
	case ARPHRD_NONE:
		ret = dump_one_gendev(ifi, kind, tb, ns, fds);
		break;
	case ARPHRD_VOID:
		ret = dump_one_voiddev(ifi, kind, tb, ns, fds);
		break;
	case ARPHRD_IPGRE:
		ret = dump_one_gre(ifi, kind, tb, ns, fds);
		break;
	case ARPHRD_SIT:
		ret = dump_one_sit(ifi, kind, tb, ns, fds);
		break;
	default:
unk:
		ret = dump_unknown_device(ifi, kind, tb, ns, fds);
		break;
	}

	return ret;
}

static int dump_one_nf(struct nlmsghdr *hdr, struct ns_id *ns, void *arg)
{
	struct cr_img *img = arg;

	if (lazy_image(img) && open_image_lazy(img))
		return -1;

	if (write_img_buf(img, hdr, hdr->nlmsg_len))
		return -1;

	return 0;
}

static int ct_restore_callback(struct nlmsghdr *nlh)
{
	struct nfgenmsg *msg;
	struct nlattr *tb[CTA_MAX+1], *tbp[CTA_PROTOINFO_MAX + 1], *tb_tcp[CTA_PROTOINFO_TCP_MAX+1];
	int err;

	msg = NLMSG_DATA(nlh);

	if (msg->nfgen_family != AF_INET && msg->nfgen_family != AF_INET6)
		return 0;

	err = nlmsg_parse(nlh, sizeof(struct nfgenmsg), tb, CTA_MAX, NULL);
	if (err < 0)
		return -1;

	if (!tb[CTA_PROTOINFO])
		return 0;

	err = nla_parse_nested(tbp, CTA_PROTOINFO_MAX, tb[CTA_PROTOINFO], NULL);
	if (err < 0)
		return -1;

	if (!tbp[CTA_PROTOINFO_TCP])
		return 0;

	err = nla_parse_nested(tb_tcp, CTA_PROTOINFO_TCP_MAX, tbp[CTA_PROTOINFO_TCP], NULL);
	if (err < 0)
		return -1;

	if (tb_tcp[CTA_PROTOINFO_TCP_FLAGS_ORIGINAL]) {
		struct nf_ct_tcp_flags *flags;

		flags = nla_data(tb_tcp[CTA_PROTOINFO_TCP_FLAGS_ORIGINAL]);
		flags->flags |= IP_CT_TCP_FLAG_BE_LIBERAL;
		flags->mask |= IP_CT_TCP_FLAG_BE_LIBERAL;
	}

	if (tb_tcp[CTA_PROTOINFO_TCP_FLAGS_REPLY]) {
		struct nf_ct_tcp_flags *flags;

		flags = nla_data(tb_tcp[CTA_PROTOINFO_TCP_FLAGS_REPLY]);
		flags->flags |= IP_CT_TCP_FLAG_BE_LIBERAL;
		flags->mask |= IP_CT_TCP_FLAG_BE_LIBERAL;
	}

	return 0;
}

static int restore_nf_ct(int pid, int type)
{
	struct nlmsghdr *nlh = NULL;
	int exit_code = -1, sk;
	struct cr_img *img;

	img = open_image(type, O_RSTR, pid);
	if (img == NULL)
		return -1;
	if (empty_image(img)) {
		close_image(img);
		return 0;
	}

	sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
	if (sk < 0) {
		pr_perror("Can't open rtnl sock for net dump");
		goto out_img;
	}

	nlh = xmalloc(sizeof(struct nlmsghdr));
	if (nlh == NULL)
		goto out;

	while (1) {
		struct nlmsghdr *p;
		int ret;

		ret = read_img_buf_eof(img, nlh, sizeof(struct nlmsghdr));
		if (ret < 0)
			goto out;
		if (ret == 0)
			break;

		p = xrealloc(nlh, nlh->nlmsg_len);
		if (p == NULL)
			goto out;
		nlh = p;

		ret = read_img_buf_eof(img, nlh + 1, nlh->nlmsg_len - sizeof(struct nlmsghdr));
		if (ret < 0)
			goto out;
		if (ret == 0) {
			pr_err("The image file was truncated\n");
			goto out;
		}

		if (type == CR_FD_NETNF_CT)
			if (ct_restore_callback(nlh))
				goto out;

		nlh->nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE;
		ret = do_rtnl_req(sk, nlh, nlh->nlmsg_len, NULL, NULL, NULL, NULL);
		if (ret)
			goto out;
	}

	exit_code = 0;
out:
	xfree(nlh);
	close(sk);
out_img:
	close_image(img);
	return exit_code;
}

static int dump_nf_ct(struct cr_imgset *fds, int type)
{
	struct cr_img *img;
	struct {
		struct nlmsghdr nlh;
		struct nfgenmsg g;
	} req;
	int sk, ret;

	pr_info("Dumping netns links\n");

	ret = sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
	if (sk < 0) {
		pr_perror("Can't open rtnl sock for net dump");
		goto out;
	}

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8);

	if (type == CR_FD_NETNF_CT)
		req.nlh.nlmsg_type |= IPCTNL_MSG_CT_GET;
	else if (type == CR_FD_NETNF_EXP)
		req.nlh.nlmsg_type |= IPCTNL_MSG_EXP_GET;
	else
		BUG();

	req.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = CR_NLMSG_SEQ;
	req.g.nfgen_family = AF_UNSPEC;

	img = img_from_set(fds, type);

	ret = do_rtnl_req(sk, &req, sizeof(req), dump_one_nf, NULL, NULL, img);
	close(sk);
out:
	return ret;

}

/*
 * When we request information about a link, the kernel shows
 * information about the pair device (netns id and idx).
 * If a pair device lives in another namespace and this namespace
 * doesn't have a netns ID in the current namespace, the kernel
 * will generate it. So we need to list all links, before dumping
 * netns indexes.
 */
static int list_links(int rtsk, void *args)
{
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;

	pr_info("Dumping netns links\n");

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = RTM_GETLINK;
	req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = CR_NLMSG_SEQ;
	req.g.rtgen_family = AF_PACKET;

	return do_rtnl_req(rtsk, &req, sizeof(req), list_one_link, NULL, NULL, args);
}

static int dump_links(int rtsk, struct ns_id *ns, struct cr_imgset *fds)
{
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;

	pr_info("Dumping netns links\n");

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = RTM_GETLINK;
	req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = CR_NLMSG_SEQ;
	req.g.rtgen_family = AF_PACKET;

	return do_rtnl_req(rtsk, &req, sizeof(req), dump_one_link, NULL, ns, fds);
}

static int restore_link_cb(struct nlmsghdr *hdr, struct ns_id *ns, void *arg)
{
	pr_info("Got response on SETLINK =)\n");
	return 0;
}

struct newlink_req {
	struct nlmsghdr h;
	struct ifinfomsg i;
	char buf[1024];
};

/* Optional extra things to be provided at the top level of the NEWLINK
 * request.
 */
struct newlink_extras {
	int link;		/* IFLA_LINK */
	int target_netns;	/* IFLA_NET_NS_FD */
};

typedef int (*link_info_t)(struct ns_id *ns, struct net_link *, struct newlink_req *);

static int populate_newlink_req(struct ns_id *ns, struct newlink_req *req,
			int msg_type, struct net_link * link,
			link_info_t link_info, struct newlink_extras *extras)
{
	NetDeviceEntry *nde = link->nde;

	memset(req, 0, sizeof(*req));

	req->h.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req->h.nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE;
	req->h.nlmsg_type = msg_type;
	req->h.nlmsg_seq = CR_NLMSG_SEQ;
	req->i.ifi_family = AF_PACKET;
	/*
	 * SETLINK is called for external devices which may
	 * have ifindex changed. Thus configure them by their
	 * name only.
	 */
	if (msg_type == RTM_NEWLINK)
		req->i.ifi_index = nde->ifindex;
	req->i.ifi_flags = nde->flags;

	if (extras) {
		if (extras->link >= 0)
			addattr_l(&req->h, sizeof(*req), IFLA_LINK, &extras->link, sizeof(extras->link));

		if (extras->target_netns >= 0)
			addattr_l(&req->h, sizeof(*req), IFLA_NET_NS_FD, &extras->target_netns, sizeof(extras->target_netns));

	}

	addattr_l(&req->h, sizeof(*req), IFLA_IFNAME, nde->name, strlen(nde->name));
	addattr_l(&req->h, sizeof(*req), IFLA_MTU, &nde->mtu, sizeof(nde->mtu));

	if (nde->has_address) {
		pr_debug("Restore ll addr (%02x:../%d) for device\n",
				(int)nde->address.data[0], (int)nde->address.len);
		addattr_l(&req->h, sizeof(*req), IFLA_ADDRESS,
				nde->address.data, nde->address.len);
	}

	if (link_info) {
		struct rtattr *linkinfo;
		int ret;

		linkinfo = NLMSG_TAIL(&req->h);
		addattr_l(&req->h, sizeof(*req), IFLA_LINKINFO, NULL, 0);

		ret = link_info(ns, link, req);
		if (ret < 0)
			return ret;

		linkinfo->rta_len = (void *)NLMSG_TAIL(&req->h) - (void *)linkinfo;
	}

	return 0;
}

static int do_rtm_link_req(int msg_type,
			struct net_link *link, int nlsk, struct ns_id *ns,
			link_info_t link_info, struct newlink_extras *extras)
{
	struct newlink_req req;

	if (populate_newlink_req(ns, &req, msg_type, link, link_info, extras) < 0)
		return -1;

	return do_rtnl_req(nlsk, &req, req.h.nlmsg_len, restore_link_cb, NULL, NULL, NULL);
}

int restore_link_parms(struct net_link *link, int nlsk)
{
	return do_rtm_link_req(RTM_SETLINK, link, nlsk, NULL, NULL, NULL);
}

static int restore_one_link(struct ns_id *ns, struct net_link *link, int nlsk,
			link_info_t link_info, struct newlink_extras *extras)
{
	pr_info("Restoring netdev %s idx %d\n", link->nde->name, link->nde->ifindex);
	return do_rtm_link_req(RTM_NEWLINK, link, nlsk, ns, link_info, extras);
}

#ifndef VETH_INFO_MAX
enum {
	VETH_INFO_UNSPEC,
	VETH_INFO_PEER,

	__VETH_INFO_MAX
#define VETH_INFO_MAX   (__VETH_INFO_MAX - 1)
};
#endif

#if IFLA_MAX <= 28
#define IFLA_NET_NS_FD	28
#endif

static int veth_peer_info(struct net_link *link, struct newlink_req *req,
						struct ns_id *ns, int ns_fd)
{
	NetDeviceEntry *nde = link->nde;
	char key[100], *val;
	struct ns_id *peer_ns = NULL;

	snprintf(key, sizeof(key), "veth[%s]", nde->name);
	val = external_lookup_by_key(key);
	if (!IS_ERR_OR_NULL(val)) {
		char *aux;

		aux = strchrnul(val, '@');
		addattr_l(&req->h, sizeof(*req), IFLA_IFNAME, val, aux - val);
		addattr_l(&req->h, sizeof(*req), IFLA_NET_NS_FD, &ns_fd, sizeof(ns_fd));
		return 0;
	}

	if (nde->has_peer_nsid) {
		struct net_link *plink;

		peer_ns = lookup_ns_by_id(nde->peer_nsid, &net_ns_desc);
		if (!peer_ns)
			goto out;
		list_for_each_entry(plink, &peer_ns->net.links, node) {
			if (plink->nde->ifindex == nde->peer_ifindex && plink->created) {
				req->h.nlmsg_type = RTM_SETLINK;
				return 0;
			}
		}
	}

	link->created = true;
	if (peer_ns) {
		addattr_l(&req->h, sizeof(*req), IFLA_NET_NS_FD, &peer_ns->net.ns_fd, sizeof(int));
		return 0;
	}
out:
	pr_err("Unknown peer net namespace\n");
	return -1;
}

static int veth_link_info(struct ns_id *ns, struct net_link *link, struct newlink_req *req)
{
	int ns_fd = get_service_fd(NS_FD_OFF);
	NetDeviceEntry *nde = link->nde;
	struct rtattr *veth_data, *peer_data;
	struct ifinfomsg ifm;

	addattr_l(&req->h, sizeof(*req), IFLA_INFO_KIND, "veth", 4);

	veth_data = NLMSG_TAIL(&req->h);
	addattr_l(&req->h, sizeof(*req), IFLA_INFO_DATA, NULL, 0);
	peer_data = NLMSG_TAIL(&req->h);
	memset(&ifm, 0, sizeof(ifm));

	/*
	 * Peer index might lay on the node root net namespace,
	 * where the device index may be already borrowed by
	 * some other device, so we should ignore it.
	 *
	 * Still if peer is laying in some other net-namespace,
	 * we should recreate the device index as well as the
	 * as we do for the master peer end.
	 */
	if (nde->has_peer_nsid)
		ifm.ifi_index = nde->peer_ifindex;
	addattr_l(&req->h, sizeof(*req), VETH_INFO_PEER, &ifm, sizeof(ifm));

	veth_peer_info(link, req, ns, ns_fd);
	peer_data->rta_len = (void *)NLMSG_TAIL(&req->h) - (void *)peer_data;
	veth_data->rta_len = (void *)NLMSG_TAIL(&req->h) - (void *)veth_data;

	return 0;
}

static int venet_link_info(struct ns_id *ns, struct net_link *link, struct newlink_req *req)
{
	int ns_fd = get_service_fd(NS_FD_OFF);
	struct rtattr *venet_data;

	BUG_ON(ns_fd < 0);

	venet_data = NLMSG_TAIL(&req->h);
	addattr_l(&req->h, sizeof(*req), IFLA_INFO_KIND, "venet", 5);
	addattr_l(&req->h, sizeof(*req), IFLA_INFO_DATA, NULL, 0);
	addattr_l(&req->h, sizeof(*req), IFLA_NET_NS_FD, &ns_fd, sizeof(ns_fd));
	venet_data->rta_len = (void *)NLMSG_TAIL(&req->h) - (void *)venet_data;

	return 0;
}

static int bridge_link_info(struct ns_id *ns, struct net_link *link, struct newlink_req *req)
{
	struct rtattr *bridge_data;

	bridge_data = NLMSG_TAIL(&req->h);
	addattr_l(&req->h, sizeof(*req), IFLA_INFO_KIND, "bridge", sizeof("bridge"));
	bridge_data->rta_len = (void *)NLMSG_TAIL(&req->h) - (void *)bridge_data;

	return 0;
}

static int changeflags(int s, char *name, short flags)
{
	struct ifreq ifr;

	strlcpy(ifr.ifr_name, name, IFNAMSIZ);
	ifr.ifr_flags = flags;

	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
		pr_perror("couldn't set flags on %s", name);
		return -1;
	}

	return 0;
}

static int macvlan_link_info(struct ns_id *ns, struct net_link *link, struct newlink_req *req)
{
	struct rtattr *macvlan_data;
	NetDeviceEntry *nde = link->nde;
	MacvlanLinkEntry *macvlan = nde->macvlan;

	if (!macvlan) {
		pr_err("Missing macvlan link entry %d\n", nde->ifindex);
		return -1;
	}

	addattr_l(&req->h, sizeof(*req), IFLA_INFO_KIND, "macvlan", 7);

	macvlan_data = NLMSG_TAIL(&req->h);
	addattr_l(&req->h, sizeof(*req), IFLA_INFO_DATA, NULL, 0);

	addattr_l(&req->h, sizeof(*req), IFLA_MACVLAN_MODE, &macvlan->mode, sizeof(macvlan->mode));

	if (macvlan->has_flags)
		addattr_l(&req->h, sizeof(*req), IFLA_MACVLAN_FLAGS, &macvlan->flags, sizeof(macvlan->flags));

	macvlan_data->rta_len = (void *)NLMSG_TAIL(&req->h) - (void *)macvlan_data;

	return 0;
}

static int userns_restore_one_link(void *arg, int fd, pid_t pid)
{
	int nlsk, ret;
	struct newlink_req *req = arg;
	int ns_fd = get_service_fd(NS_FD_OFF), rst = -1;

	if (!(root_ns_mask & CLONE_NEWUSER)) {
		if (switch_ns_by_fd(ns_fd, &net_ns_desc, &rst))
			return -1;
	}

	nlsk = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nlsk < 0) {
		pr_perror("Can't create nlk socket");
		ret = -1;
		goto out;
	}

	addattr_l(&req->h, sizeof(*req), IFLA_NET_NS_FD, &fd, sizeof(fd));

	ret = do_rtnl_req(nlsk, req, req->h.nlmsg_len, restore_link_cb, NULL, NULL, NULL);
	close(nlsk);

out:
	if (rst >= 0 && restore_ns(rst, &net_ns_desc) < 0)
		ret = -1;
	return ret;
}

static int restore_one_macvlan(struct ns_id *ns, struct net_link *link, int nlsk)
{
	struct newlink_extras extras = {
		.link = -1,
		.target_netns = -1,
	};
	char key[100], *val;
	int my_netns = -1, ret = -1;
	NetDeviceEntry *nde = link->nde;

	snprintf(key, sizeof(key), "macvlan[%s]", nde->name);
	val = external_lookup_data(key);
	if (IS_ERR_OR_NULL(val)) {
		pr_err("a macvlan parent for %s is required\n", nde->name);
		return -1;
	}

	/* link and netns_id are used to identify the master device to plug our
	 * macvlan slave into. We identify the destination via setting
	 * IFLA_NET_NS_FD to my_netns, but we have to do that in two different
	 * ways: in the userns case, we send the fd across to usernsd and set
	 * it there, whereas in the non-userns case we can just set it here,
	 * since we can just use a socket from criu's net ns given to us by
	 * restore_links(). We need to do this two different ways because
	 * CAP_NET_ADMIN is required in both namespaces, which we don't have in
	 * the userns case, and usernsd doesn't exist in the non-userns case.
	 */
	extras.link = (int) (unsigned long) val;

	my_netns = open_proc(PROC_SELF, "ns/net");
	if (my_netns < 0)
		return -1;

	{
		struct newlink_req req;

		if (populate_newlink_req(ns, &req, RTM_NEWLINK, link, macvlan_link_info, &extras) < 0)
			goto out;

		if (userns_call(userns_restore_one_link, 0, &req, sizeof(req), my_netns) < 0) {
			pr_err("couldn't restore macvlan interface %s via usernsd\n", nde->name);
			goto out;
		}
	}

	ret = 0;
out:
	if (my_netns >= 0)
		close(my_netns);
	return ret;
}

static int sit_link_info(struct ns_id *ns, struct net_link *link, struct newlink_req *req)
{
	NetDeviceEntry *nde = link->nde;
	struct rtattr *sit_data;
	SitEntry *se = nde->sit;

	if (!se) {
		pr_err("Missing sit entry %d\n", nde->ifindex);
		return -1;
	}

	addattr_l(&req->h, sizeof(*req), IFLA_INFO_KIND, "sit", 3);
	sit_data = NLMSG_TAIL(&req->h);
	addattr_l(&req->h, sizeof(*req), IFLA_INFO_DATA, NULL, 0);

#define DECODE_ENTRY(__type, __ifla, __proto) do {				\
			__type aux;						\
			if (se->has_##__proto) {				\
				aux = se->__proto;				\
				addattr_l(&req->h, sizeof(*req), __ifla,	\
						&aux, sizeof(__type));		\
			}							\
		} while (0)

	if (se->n_local) {
		if (se->n_local != 1) {
			pr_err("Too long local addr for sit\n");
			return -1;
		}
		addattr_l(&req->h, sizeof(*req), IFLA_IPTUN_LOCAL, se->local, sizeof(u32));
	}

	if (se->n_remote) {
		if (se->n_remote != 1) {
			pr_err("Too long remote addr for sit\n");
			return -1;
		}
		addattr_l(&req->h, sizeof(*req), IFLA_IPTUN_REMOTE, se->remote, sizeof(u32));
	}

	DECODE_ENTRY(u32, IFLA_IPTUN_LINK,  link);
	DECODE_ENTRY(u8,  IFLA_IPTUN_TTL,   ttl);
	DECODE_ENTRY(u8,  IFLA_IPTUN_TOS,   tos);
	DECODE_ENTRY(u16, IFLA_IPTUN_FLAGS, flags);
	DECODE_ENTRY(u8,  IFLA_IPTUN_PROTO, proto);

	if (se->has_pmtudisc && se->pmtudisc) {
		u8 aux = 1;
		addattr_l(&req->h, sizeof(*req), IFLA_IPTUN_PMTUDISC, &aux, sizeof(u8));
	}

	DECODE_ENTRY(u16, IFLA_IPTUN_ENCAP_TYPE,  encap_type);
	DECODE_ENTRY(u16, IFLA_IPTUN_ENCAP_FLAGS, encap_flags);
	DECODE_ENTRY(u16, IFLA_IPTUN_ENCAP_SPORT, encap_sport);
	DECODE_ENTRY(u16, IFLA_IPTUN_ENCAP_DPORT, encap_dport);

	if (se->has_rd_prefixlen) {
		u16 aux;

		if (se->n_rd_prefix != 4) {
			pr_err("Bad 6rd prefixlen for sit\n");
			return -1;
		}

		aux = se->rd_prefixlen;
		addattr_l(&req->h, sizeof(*req), IFLA_IPTUN_6RD_PREFIXLEN, &aux, sizeof(u16));
		addattr_l(&req->h, sizeof(*req), IFLA_IPTUN_6RD_PREFIX, se->rd_prefix, 4 * sizeof(u32));

		if (!se->has_relay_prefixlen)
			goto skip;

		if (se->n_relay_prefix != 1) {
			pr_err("Bad 6rd relay prefixlen for sit\n");
			return -1;
		}

		aux = se->relay_prefixlen;
		addattr_l(&req->h, sizeof(*req), IFLA_IPTUN_6RD_RELAY_PREFIXLEN, &aux, sizeof(u16));
		addattr_l(&req->h, sizeof(*req), IFLA_IPTUN_6RD_RELAY_PREFIX, se->relay_prefix, sizeof(u32));
skip:;
	}

#undef DECODE_ENTRY

	sit_data->rta_len = (void *)NLMSG_TAIL(&req->h) - (void *)sit_data;

	return 0;
}

static int __restore_link(struct ns_id *ns, struct net_link *link, int nlsk)
{
	NetDeviceEntry *nde = link->nde;

	pr_info("Restoring link %s type %d\n", nde->name, nde->type);

	switch (nde->type) {
	case ND_TYPE__LOOPBACK: /* fallthrough */
	case ND_TYPE__EXTLINK:  /* see comment in images/netdev.proto */
		return restore_link_parms(link, nlsk);
	case ND_TYPE__VENET:
		return restore_one_link(ns, link, nlsk, venet_link_info, NULL);
	case ND_TYPE__VETH:
		return restore_one_link(ns, link, nlsk, veth_link_info, NULL);
	case ND_TYPE__TUN:
		return restore_one_tun(ns, link, nlsk);
	case ND_TYPE__BRIDGE:
		return restore_one_link(ns, link, nlsk, bridge_link_info, NULL);
	case ND_TYPE__MACVLAN:
		return restore_one_macvlan(ns, link, nlsk);
	case ND_TYPE__SIT:
		return restore_one_link(ns, link, nlsk, sit_link_info, NULL);
	default:
		pr_err("Unsupported link type %d\n", link->nde->type);
		break;
	}

	return -1;
}

static int read_links(struct ns_id *ns)
{
	int ret = -1, id = ns->id;
	struct cr_img *img;
	NetDeviceEntry *nde;

	img = open_image(CR_FD_NETDEV, O_RSTR, id);
	if (!img)
		return -1;

	while (1) {
		struct net_link *link;

		ret = pb_read_one_eof(img, &nde, PB_NETDEV);
		if (ret <= 0)
			break;

		link = xmalloc(sizeof(*link));
		if (link == NULL) {
			ret = -1;
			net_device_entry__free_unpacked(nde, NULL);
			break;
		}

		link->nde = nde;
		link->created = 0;
		list_add(&link->node, &ns->net.links);
	}
	close_image(img);

	return ret;
}

static int restore_link(int nlsk, struct ns_id *ns, struct net_link *link)
{
	NetDeviceEntry *nde = link->nde;
	NetnsEntry **def_netns = &ns->net.netns;
	int ret;

	ret = __restore_link(ns, link, nlsk);
	if (ret) {
		pr_err("Can't restore link: %d\n", ret);
		goto exit;
	}

	/*
	 * optimize restore of devices configuration except lo
	 * lo is created with namespace and before default is set
	 * so we can't optimize its restore
	 */
	if (nde->type == ND_TYPE__LOOPBACK)
		def_netns = NULL;

	if (nde->conf4)
		ret = ipv4_conf_op(nde->name, nde->conf4, nde->n_conf4, CTL_WRITE, def_netns ? (*def_netns)->def_conf4 : NULL);
	else if (nde->conf)
		ret = ipv4_conf_op_old(nde->name, nde->conf, nde->n_conf, CTL_WRITE, def_netns ? (*def_netns)->def_conf : NULL);
	if (ret)
		goto exit;

	if (nde->conf6)
		ret = ipv6_conf_op(nde->name, nde->conf6, nde->n_conf6, CTL_WRITE, def_netns ? (*def_netns)->def_conf6 : NULL);
exit:
	return ret;
}

static int restore_master_link(int nlsk, struct ns_id *ns, struct net_link *link)
{
	struct newlink_req req;

	memset(&req, 0, sizeof(req));

	req.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.h.nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE;
	req.h.nlmsg_type = RTM_SETLINK;
	req.h.nlmsg_seq = CR_NLMSG_SEQ;
	req.i.ifi_family = AF_PACKET;
	req.i.ifi_index = link->nde->ifindex;
	req.i.ifi_flags = link->nde->flags;

	addattr_l(&req.h, sizeof(req), IFLA_MASTER,
			&link->nde->master, sizeof(link->nde->master));

	return do_rtnl_req(nlsk, &req, req.h.nlmsg_len, restore_link_cb, NULL, NULL, NULL);
}

struct net_link *lookup_net_link(struct ns_id *ns, uint32_t ifindex)
{
	struct net_link *link;

	list_for_each_entry(link, &ns->net.links, node)
		if (link->nde->ifindex == ifindex)
			return link;

	return NULL;
}

static int __restore_links(struct ns_id *nsid, int *nrlinks, int *nrcreated)
{
	struct net_link *link, *t;
	int ret;

	list_for_each_entry_safe(link, t, &nsid->net.links, node) {
		struct net_link *mlink = NULL;

		if (link->created)
			continue;

		(*nrlinks)++;

		pr_debug("Try to restore a link %d:%d:%s",
				nsid->id, link->nde->ifindex, link->nde->name);
		if (link->nde->has_master) {
			mlink = lookup_net_link(nsid, link->nde->master);
			if (mlink == NULL) {
				pr_err("Unable to find the %d master\n", link->nde->master);
				return -1;
			}

			if (!mlink->created) {
				pr_debug("The master %d:%d:%s isn't created yet",
					nsid->id, mlink->nde->ifindex, mlink->nde->name);
				continue;
			}
		}

		ret = restore_link(nsid->net.nlsk, nsid, link);
		if (ret < 0)
			return -1;

		if (ret == 0) {
			(*nrcreated)++;
			link->created = true;

			if (mlink && restore_master_link(nsid->net.nlsk, nsid, link))
				return -1;
		}
	}

	return 0;
}

static int restore_links(void)
{
	int nrcreated, nrlinks;
	struct ns_id *nsid;

	while (true) {
		nrcreated = 0;
		nrlinks = 0;
		for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
			if (nsid->nd != &net_ns_desc)
				continue;

			if (switch_ns_by_fd(nsid->net.ns_fd, &net_ns_desc, NULL))
				return -1;

			if (__restore_links(nsid, &nrlinks, &nrcreated))
				return -1;
		}

		if (nrcreated == nrlinks)
			break;
		if (nrcreated == 0) {
			pr_err("Unable to restore network links\n");
			return -1;
		}
	}

	return 0;
}


static int run_ip_tool(char *arg1, char *arg2, char *arg3, char *arg4, int fdin, int fdout, unsigned flags)
{
	char *ip_tool_cmd;
	int ret;

	pr_debug("\tRunning ip %s %s %s %s\n", arg1, arg2, arg3 ? : "", arg4 ? : "");

	ip_tool_cmd = getenv("CR_IP_TOOL");
	if (!ip_tool_cmd)
		ip_tool_cmd = "ip";

	ret = cr_system(fdin, fdout, -1, ip_tool_cmd,
				(char *[]) { "ip", arg1, arg2, arg3, arg4, NULL }, flags);
	if (ret) {
		if (!(flags & CRS_CAN_FAIL))
			pr_err("IP tool failed on %s %s %s %s\n", arg1, arg2, arg3 ? : "", arg4 ? : "");
		return -1;
	}

	return 0;
}

static int run_iptables_tool(char *def_cmd, int fdin, int fdout)
{
	int ret;
	char *cmd;

	cmd = getenv("CR_IPTABLES");
	if (!cmd)
		cmd = def_cmd;
	pr_debug("\tRunning %s for %s\n", cmd, def_cmd);
	ret = cr_system(fdin, fdout, -1, "sh", (char *[]) { "sh", "-c", cmd, NULL }, 0);
	if (ret)
		pr_err("%s failed\n", def_cmd);

	return ret;
}

static inline int dump_ifaddr(struct cr_imgset *fds)
{
	struct cr_img *img = img_from_set(fds, CR_FD_IFADDR);
	return run_ip_tool("addr", "save", NULL, NULL, -1, img_raw_fd(img), 0);
}

static inline int dump_route(struct cr_imgset *fds)
{
	struct cr_img *img;

	img = img_from_set(fds, CR_FD_ROUTE);
	if (run_ip_tool("route", "save", NULL, NULL, -1, img_raw_fd(img), 0))
		return -1;

	/* If ipv6 is disabled, "ip -6 route dump" dumps all routes */
	if (!kdat.ipv6)
		return 0;

	img = img_from_set(fds, CR_FD_ROUTE6);
	if (run_ip_tool("-6", "route", "save", NULL, -1, img_raw_fd(img), 0))
		return -1;

	return 0;
}

static inline int dump_rule(struct cr_imgset *fds)
{
	struct cr_img *img;
	char *path;

	img = img_from_set(fds, CR_FD_RULE);
	path = xstrdup(img->path);

	if (!path)
		return -1;

	if (run_ip_tool("rule", "save", NULL, NULL, -1, img_raw_fd(img), CRS_CAN_FAIL)) {
		pr_warn("Check if \"ip rule save\" is supported!\n");
		unlinkat(get_service_fd(IMG_FD_OFF), path, 0);
	}

	free(path);

	return 0;
}

static inline int dump_iptables(struct cr_imgset *fds)
{
	struct cr_img *img;

	img = img_from_set(fds, CR_FD_IPTABLES);
	if (run_iptables_tool("iptables-save", -1, img_raw_fd(img)))
		return -1;

	if (kdat.ipv6) {
		img = img_from_set(fds, CR_FD_IP6TABLES);
		if (run_iptables_tool("ip6tables-save", -1, img_raw_fd(img)))
			return -1;
	}

	return 0;
}

#if defined(CONFIG_HAS_NFTABLES_LIB_API_0) || defined(CONFIG_HAS_NFTABLES_LIB_API_1)
static inline int dump_nftables(struct cr_imgset *fds)
{
	int ret = -1;
	struct cr_img *img;
	int img_fd;
	FILE *fp;
	struct nft_ctx *nft;

	nft = nft_ctx_new(NFT_CTX_DEFAULT);
	if (!nft)
		return -1;

	img = img_from_set(fds, CR_FD_NFTABLES);
	img_fd = dup(img_raw_fd(img));
	if (img_fd < 0) {
		pr_perror("dup() failed");
		goto nft_ctx_free_out;
	}

	fp = fdopen(img_fd, "w");
	if (!fp) {
		pr_perror("fdopen() failed");
		close(img_fd);
		goto nft_ctx_free_out;
	}

	nft_ctx_set_output(nft, fp);
#define DUMP_NFTABLES_CMD "list ruleset"
#if defined(CONFIG_HAS_NFTABLES_LIB_API_0)
	if (nft_run_cmd_from_buffer(nft, DUMP_NFTABLES_CMD, strlen(DUMP_NFTABLES_CMD)))
#elif defined(CONFIG_HAS_NFTABLES_LIB_API_1)
	if (nft_run_cmd_from_buffer(nft, DUMP_NFTABLES_CMD))
#else
	BUILD_BUG_ON(1);
#endif
		goto fp_close_out;

	ret = 0;

fp_close_out:
	fclose(fp);
nft_ctx_free_out:
	nft_ctx_free(nft);

	return ret;
}
#endif

static int dump_netns_conf(struct ns_id *ns, struct cr_imgset *fds)
{
	void *buf, *o_buf;
	int ret = -1;
	int i;
	NetnsEntry netns = NETNS_ENTRY__INIT;
	SysctlEntry *unix_confs = NULL;
	size_t sizex = ARRAY_SIZE(unix_conf_entries);
	SysctlEntry *def_confs4 = NULL, *all_confs4 = NULL;
	int size4 = ARRAY_SIZE(devconfs4);
	SysctlEntry *def_confs6 = NULL, *all_confs6 = NULL;
	int size6 = ARRAY_SIZE(devconfs6);
	char def_stable_secret[MAX_STR_CONF_LEN + 1] = {};
	char all_stable_secret[MAX_STR_CONF_LEN + 1] = {};
	NetnsId	*ids;
	struct netns_id *p;

	i = 0;
	list_for_each_entry(p, &ns->net.ids, node)
		i++;

	o_buf = buf = xmalloc(
			i * (sizeof(NetnsId*) + sizeof(NetnsId)) +
			size4 * (sizeof(SysctlEntry*) + sizeof(SysctlEntry)) * 2 +
			size6 * (sizeof(SysctlEntry*) + sizeof(SysctlEntry)) * 2 +
			sizex * (sizeof(SysctlEntry*) + sizeof(SysctlEntry))
		     );
	if (!buf)
		goto out;

	netns.nsids = xptr_pull_s(&buf, i * sizeof(NetnsId*));
	ids = xptr_pull_s(&buf, i * sizeof(NetnsId));
	i = 0;
	list_for_each_entry(p, &ns->net.ids, node) {
		netns_id__init(&ids[i]);
		ids[i].target_ns_id = p->target_ns_id;
		ids[i].netnsid_value = p->netnsid_value;
		netns.nsids[i] = ids + i;
		i++;
	}
	netns.n_nsids = i;

	netns.n_def_conf4 = size4;
	netns.n_all_conf4 = size4;
	netns.def_conf4 = xptr_pull_s(&buf, size4 * sizeof(SysctlEntry*));
	netns.all_conf4 = xptr_pull_s(&buf, size4 * sizeof(SysctlEntry*));
	def_confs4 = xptr_pull_s(&buf, size4 * sizeof(SysctlEntry));
	all_confs4 = xptr_pull_s(&buf, size4 * sizeof(SysctlEntry));

	for (i = 0; i < size4; i++) {
		sysctl_entry__init(&def_confs4[i]);
		sysctl_entry__init(&all_confs4[i]);
		netns.def_conf4[i] = &def_confs4[i];
		netns.all_conf4[i] = &all_confs4[i];
		netns.def_conf4[i]->type = CTL_32;
		netns.all_conf4[i]->type = CTL_32;
	}

	netns.n_def_conf6 = size6;
	netns.n_all_conf6 = size6;
	netns.def_conf6 = xptr_pull_s(&buf, size6 * sizeof(SysctlEntry*));
	netns.all_conf6 = xptr_pull_s(&buf, size6 * sizeof(SysctlEntry*));
	def_confs6 = xptr_pull_s(&buf, size6 * sizeof(SysctlEntry));
	all_confs6 = xptr_pull_s(&buf, size6 * sizeof(SysctlEntry));

	for (i = 0; i < size6; i++) {
		sysctl_entry__init(&def_confs6[i]);
		sysctl_entry__init(&all_confs6[i]);
		netns.def_conf6[i] = &def_confs6[i];
		netns.all_conf6[i] = &all_confs6[i];
		if (strcmp(devconfs6[i], "stable_secret")) {
			netns.def_conf6[i]->type = SYSCTL_TYPE__CTL_32;
			netns.all_conf6[i]->type = SYSCTL_TYPE__CTL_32;
		} else {
			netns.def_conf6[i]->type = SYSCTL_TYPE__CTL_STR;
			netns.all_conf6[i]->type = SYSCTL_TYPE__CTL_STR;
			netns.def_conf6[i]->sarg = def_stable_secret;
			netns.all_conf6[i]->sarg = all_stable_secret;
		}
	}

	netns.n_unix_conf = sizex;
	netns.unix_conf = xptr_pull_s(&buf, sizex * sizeof(SysctlEntry*));
	unix_confs = xptr_pull_s(&buf, sizex * sizeof(SysctlEntry));

	for (i = 0; i < sizex; i++) {
		sysctl_entry__init(&unix_confs[i]);
		netns.unix_conf[i] = &unix_confs[i];
		netns.unix_conf[i]->type = SYSCTL_TYPE__CTL_32;
	}

	ret = ipv4_conf_op("default", netns.def_conf4, size4, CTL_READ, NULL);
	if (ret < 0)
		goto err_free;
	ret = ipv4_conf_op("all", netns.all_conf4, size4, CTL_READ, NULL);
	if (ret < 0)
		goto err_free;

	ret = ipv6_conf_op("default", netns.def_conf6, size6, CTL_READ, NULL);
	if (ret < 0)
		goto err_free;
	ret = ipv6_conf_op("all", netns.all_conf6, size6, CTL_READ, NULL);
	if (ret < 0)
		goto err_free;

	ret = unix_conf_op(&netns.unix_conf, &netns.n_unix_conf, CTL_READ);
	if (ret < 0)
		goto err_free;

	ret = pb_write_one(img_from_set(fds, CR_FD_NETNS), &netns, PB_NETNS);
err_free:
	xfree(o_buf);
out:
	return ret;
}

static int restore_ip_dump(int type, int pid, char *cmd)
{
	int ret = -1;
	struct cr_img *img;

	img = open_image(type, O_RSTR, pid);
	if (empty_image(img)) {
		close_image(img);
		return 0;
	}
	if (img) {
		ret = run_ip_tool(cmd, "restore", NULL, NULL, img_raw_fd(img), -1, 0);
		close_image(img);
	}

	return ret;
}

static inline int restore_ifaddr(int pid)
{
	return restore_ip_dump(CR_FD_IFADDR, pid, "addr");
}

static inline int restore_route(int pid)
{
	if (restore_ip_dump(CR_FD_ROUTE, pid, "route"))
		return -1;

	if (restore_ip_dump(CR_FD_ROUTE6, pid, "route"))
		return -1;

	return 0;
}

static inline int restore_rule(int pid)
{
	struct cr_img *img;
	int ret = 0;

	img = open_image(CR_FD_RULE, O_RSTR, pid);
	if (!img) {
		ret = -1;
		goto out;
	}

	if (empty_image(img))
		goto close;

	/*
	 * Delete 3 default rules to prevent duplicates. See kernel's
	 * function fib_default_rules_init() for the details.
	 */
	run_ip_tool("rule", "flush",  NULL,    NULL,    -1, -1, 0);
	run_ip_tool("rule", "delete", "table", "local", -1, -1, 0);

	if (restore_ip_dump(CR_FD_RULE, pid, "rule"))
		ret = -1;
close:
	close_image(img);
out:
	return ret;
}

/*
 * iptables-restore is executed from a target userns and it may have not enough
 * rights to open /run/xtables.lock. Here we try to workaround this problem.
 */
static int prepare_xtable_lock(void)
{
	int fd;

	fd = open("/run/xtables.lock", O_RDONLY);
	if (fd >= 0) {
		close(fd);
		return 0;
	}

	/*
	 * __prepare_net_namespaces is executed in a separate process,
	 * so a mount namespace can be changed.
	 */
	if (unshare(CLONE_NEWNS)) {
		pr_perror("Unable to create a mount namespace");
		return -1;
	}

	if (mount(NULL, "/",  NULL, MS_SLAVE | MS_REC, NULL)) {
		pr_perror("Unable to conver mounts to slave mounts");
		return -1;
	}
	/*
	 * /run/xtables.lock may not exist, so we can't just bind-mount a file
	 * over it.
	 * A new mount will not be propagated to the host mount namespace,
	 * because we are in another userns.
	 */

	if (mount("criu-xtable-lock", "/run", "tmpfs", 0, NULL)) {
		pr_perror("Unable to mount tmpfs into /run");
		return -1;
	}

	return 0;
}

static inline int restore_iptables(int pid)
{
	int ret = -1;
	struct cr_img *img;

	img = open_image(CR_FD_IPTABLES, O_RSTR, pid);
	if (img == NULL)
		return -1;
	if (empty_image(img)) {
		ret = 0;
		goto ipt6;
	}

	ret = run_iptables_tool("iptables-restore -w", img_raw_fd(img), -1);
	close_image(img);
	if (ret)
		return ret;
ipt6:
	img = open_image(CR_FD_IP6TABLES, O_RSTR, pid);
	if (img == NULL)
		return -1;
	if (empty_image(img))
		goto out;

	ret = run_iptables_tool("ip6tables-restore -w", img_raw_fd(img), -1);
out:
	close_image(img);

	return ret;
}

#if defined(CONFIG_HAS_NFTABLES_LIB_API_0) || defined(CONFIG_HAS_NFTABLES_LIB_API_1)
static inline int restore_nftables(int pid)
{
	int ret = -1;
	struct cr_img *img;
	struct nft_ctx *nft;
	off_t img_data_size;
	char *buf;

	img = open_image(CR_FD_NFTABLES, O_RSTR, pid);
	if (img == NULL)
		return -1;
	if (empty_image(img)) {
		/* Backward compatibility */
		pr_info("Skipping nft restore, no image");
		ret = 0;
		goto image_close_out;
	}

	if ((img_data_size = img_raw_size(img)) < 0)
		goto image_close_out;

	if (read_img_str(img, &buf, img_data_size) < 0)
		goto image_close_out;

	nft = nft_ctx_new(NFT_CTX_DEFAULT);
	if (!nft)
		goto buf_free_out;

	if (nft_ctx_buffer_output(nft) || nft_ctx_buffer_error(nft) ||
#if defined(CONFIG_HAS_NFTABLES_LIB_API_0)
		nft_run_cmd_from_buffer(nft, buf, strlen(buf)))
#elif defined(CONFIG_HAS_NFTABLES_LIB_API_1)
		nft_run_cmd_from_buffer(nft, buf))
#else
	{
		BUILD_BUG_ON(1);
	}
#endif
		goto nft_ctx_free_out;

	ret = 0;

nft_ctx_free_out:
	nft_ctx_free(nft);
buf_free_out:
	xfree(buf);
image_close_out:
	close_image(img);

	return ret;
}
#endif

int read_net_ns_img(void)
{
	struct ns_id *ns;

	if (!(root_ns_mask & CLONE_NEWNET))
		return 0;

	for (ns = ns_ids; ns != NULL; ns = ns->next) {
		struct cr_img *img;
		int ret;

		if (ns->nd != &net_ns_desc)
			continue;

		img = open_image(CR_FD_NETNS, O_RSTR, ns->id);
		if (!img)
			return -1;

		if (empty_image(img)) {
			/* Backward compatibility */
			close_image(img);
			continue;
		}

		ret = pb_read_one(img, &ns->net.netns, PB_NETNS);
		close_image(img);
		if (ret < 0) {
			pr_err("Can not read netns object\n");
			return -1;
		}
		ns->ext_key = ns->net.netns->ext_key;
	}

	return 0;
}

static int restore_netns_conf(struct ns_id *ns)
{
	NetnsEntry *netns = ns->net.netns;
	int ret = 0;

	if (ns->net.netns == NULL)
		/* Backward compatibility */
		goto out;

	if ((netns)->def_conf4) {
		ret = ipv4_conf_op("all", (netns)->all_conf4, (netns)->n_all_conf4, CTL_WRITE, NULL);
		if (ret)
			goto out;
		ret = ipv4_conf_op("default", (netns)->def_conf4, (netns)->n_def_conf4, CTL_WRITE, NULL);
		if (ret)
			goto out;
	} else if ((netns)->def_conf) {
		/* Backward compatibility */
		ret = ipv4_conf_op_old("all", (netns)->all_conf, (netns)->n_all_conf, CTL_WRITE, NULL);
		if (ret)
			goto out;
		ret = ipv4_conf_op_old("default", (netns)->def_conf, (netns)->n_def_conf, CTL_WRITE, NULL);
		if (ret)
			goto out;
	}

	if ((netns)->def_conf6) {
		ret = ipv6_conf_op("all", (netns)->all_conf6, (netns)->n_all_conf6, CTL_WRITE, NULL);
		if (ret)
			goto out;
		ret = ipv6_conf_op("default", (netns)->def_conf6, (netns)->n_def_conf6, CTL_WRITE, NULL);
	}

	if ((netns)->unix_conf) {
		ret = unix_conf_op(&(netns)->unix_conf, &(netns)->n_unix_conf, CTL_WRITE);
		if (ret)
			goto out;
	}

	ns->net.netns = netns;
out:
	return ret;
}

static int mount_ns_sysfs(void)
{
	char sys_mount[] = "crtools-sys.XXXXXX";

	BUG_ON(ns_sysfs_fd != -1);

	if (kdat.has_fsopen) {
		ns_sysfs_fd = mount_detached_fs("sysfs");
		return ns_sysfs_fd >= 0 ? 0 : -1;
	}

	/*
	 * A new mntns is required to avoid the race between
	 * open_detach_mount and creating mntns.
	 */
	if (unshare(CLONE_NEWNS)) {
		pr_perror("Can't create new mount namespace");
		return -1;
	}

	if (mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL)) {
		pr_perror("Can't mark the root mount as private");
		return -1;
	}

	if (mkdtemp(sys_mount) == NULL) {
		pr_perror("mkdtemp failed %s", sys_mount);
		return -1;
	}

	/*
	 * The setns() is called, so we're in proper context,
	 * no need in pulling the mountpoint from parasite.
	 */
	pr_info("Mount ns' sysfs in %s\n", sys_mount);
	if (mount("sysfs", sys_mount, "sysfs", MS_MGC_VAL, NULL)) {
		pr_perror("mount failed");
		rmdir(sys_mount);
		return -1;
	}

	ns_sysfs_fd = open_detach_mount(sys_mount);
	return ns_sysfs_fd >= 0 ? 0 : -1;
}

struct net_id_arg {
	struct ns_id *ns;
	int sk;
};

static int collect_netns_id(struct ns_id *ns, void *oarg)
{
	struct net_id_arg *arg = oarg;
	struct netns_id *netns_id;
	int nsid = -1;

	if (net_get_nsid(arg->sk, ns->ns_pid, &nsid))
		return -1;

	if (nsid == -1)
		return 0;

	netns_id = xmalloc(sizeof(*netns_id));
	if (!netns_id)
		return -1;

	pr_debug("Found the %d id for %d in %d\n", nsid, ns->id, arg->ns->id);
	netns_id->target_ns_id = ns->id;
	netns_id->netnsid_value = nsid;

	list_add(&netns_id->node, &arg->ns->net.ids);

	return 0;
}

static int dump_netns_ids(int rtsk, struct ns_id *ns)
{
	struct net_id_arg arg = {
		.ns = ns,
		.sk = rtsk,
	};
	return walk_namespaces(&net_ns_desc, collect_netns_id,
			(void *)&arg);
}

int net_set_ext(struct ns_id *ns)
{
	int fd, ret;

	fd = inherit_fd_lookup_id(ns->ext_key);
	if (fd < 0) {
		pr_err("Unable to find an external netns: %s\n", ns->ext_key);
		return -1;
	}

	ret = switch_ns_by_fd(fd, &net_ns_desc, NULL);
	close(fd);

	return ret;
}

int dump_net_ns(struct ns_id *ns)
{
	struct cr_imgset *fds;
	int ret;

	fds = cr_imgset_open(ns->id, NETNS, O_DUMP);
	if (fds == NULL)
		return -1;

	ret = mount_ns_sysfs();
	if (ns->ext_key) {
		NetnsEntry netns = NETNS_ENTRY__INIT;

		netns.ext_key = ns->ext_key;
		ret = pb_write_one(img_from_set(fds, CR_FD_NETNS), &netns, PB_NETNS);
		if (ret)
			goto out;
	} else if (!(opts.empty_ns & CLONE_NEWNET)) {
		int sk;

		sk = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
		if (sk < 0) {
			pr_perror("Can't open rtnl sock for net dump");
			ret = -1;
		}

		/*
		 * If a device has a pair in another netns, the kernel generates
		 * a netns ID for this netns when we request information about
		 * the link.
		 * So we need to get information about all links to be sure that
		 * all related net namespaces have got netns id-s in this netns.
		 */
		if (!ret)
			ret = list_links(sk, NULL);
		if (!ret)
			ret = dump_netns_ids(sk, ns);
		if (!ret)
			ret = dump_links(sk, ns, fds);

		close(sk);

		if (!ret)
			ret = dump_ifaddr(fds);
		if (!ret)
			ret = dump_route(fds);
		if (!ret)
			ret = dump_rule(fds);
		if (!ret)
			ret = dump_iptables(fds);
#if defined(CONFIG_HAS_NFTABLES_LIB_API_0) || defined(CONFIG_HAS_NFTABLES_LIB_API_1)
		if (!ret)
			ret = dump_nftables(fds);
#endif
		if (!ret)
			ret = dump_netns_conf(ns, fds);
	} else if (ns->type != NS_ROOT) {
		pr_err("Unable to dump more than one netns if the --emptyns is set\n");
		ret = -1;
	}
	if (!ret)
		ret = dump_nf_ct(fds, CR_FD_NETNF_CT);
	if (!ret)
		ret = dump_nf_ct(fds, CR_FD_NETNF_EXP);

out:
	close(ns_sysfs_fd);
	ns_sysfs_fd = -1;

	close_cr_imgset(&fds);
	return ret;
}

static int net_set_nsid(int rtsk, int fd, int nsid);
static int restore_netns_ids(struct ns_id *ns)
{
	int i, sk, exit_code = -1;

	if (!ns->net.netns)
		return 0;

	sk = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sk < 0) {
		pr_perror("Can't open rtnl sock for net dump");
		return -1;
	}

	for (i = 0; i < ns->net.netns->n_nsids; i++) {
		struct ns_id *tg_ns;
		struct netns_id *id;

		id = xmalloc(sizeof(*id));
		if (!id)
			goto out;
		id->target_ns_id = ns->net.netns->nsids[i]->target_ns_id;
		id->netnsid_value = ns->net.netns->nsids[i]->netnsid_value;
		list_add(&id->node, &ns->net.ids);

		tg_ns = lookup_ns_by_id(id->target_ns_id, &net_ns_desc);
		if (tg_ns == NULL) {
			pr_err("Unknown namespace: %d\n", id->target_ns_id);
			goto out;
		}

		if (net_set_nsid(sk, tg_ns->net.ns_fd, id->netnsid_value))
			goto out;
	}

	exit_code = 0;
out:
	close(sk);

	return exit_code;
}

static int prepare_net_ns_first_stage(struct ns_id *ns)
{
	int ret = 0;

	if (ns->ext_key || (opts.empty_ns & CLONE_NEWNET))
		return 0;

	ret = restore_netns_conf(ns);
	if (!ret)
		ret = restore_netns_ids(ns);
	if (!ret)
		ret = read_links(ns);

	return ret;
}

static int prepare_net_ns_second_stage(struct ns_id *ns)
{
	int ret = 0, nsid = ns->id;

	if (!(opts.empty_ns & CLONE_NEWNET) && !ns->ext_key) {
		if (ns->net.netns)
			netns_entry__free_unpacked(ns->net.netns, NULL);

		if (!ret)
			ret = restore_ifaddr(nsid);
		if (!ret)
			ret = restore_route(nsid);
		if (!ret)
			ret = restore_rule(nsid);
		if (!ret)
			ret = restore_iptables(nsid);
#if defined(CONFIG_HAS_NFTABLES_LIB_API_0) || defined(CONFIG_HAS_NFTABLES_LIB_API_1)
		if (!ret)
			ret = restore_nftables(nsid);
#endif
	}

	if (!ret)
		ret = restore_nf_ct(nsid, CR_FD_NETNF_CT);
	if (!ret)
		ret = restore_nf_ct(nsid, CR_FD_NETNF_EXP);

	if (!ret) {
		int fd = ns->net.ns_fd;

		ns->net.nsfd_id = fdstore_add(fd);
		if (ns->net.nsfd_id < 0)
			ret = -1;
		close(fd);
	}

	ns->ns_populated = true;

	return ret;
}

static int open_net_ns(struct ns_id *nsid)
{
	int fd;

	/* Pin one with a file descriptor */
	fd = open_proc(PROC_SELF, "ns/net");
	if (fd < 0)
		return -1;
	nsid->net.ns_fd = fd;

	return 0;
}

static int do_create_net_ns(struct ns_id *ns)
{
	int ret;

	if (ns->ext_key)
		ret = net_set_ext(ns);
	else
		ret = unshare(CLONE_NEWNET);

	if (ret) {
		pr_perror("Unable to create a new netns");
		return -1;
	}
	if (open_net_ns(ns))
		return -1;
	return 0;
}

static int __prepare_net_namespaces(void *unused)
{
	struct ns_id *nsid;
	int root_ns;

	if (prepare_xtable_lock())
		return -1;

	root_ns = open_proc(PROC_SELF, "ns/net");
	if (root_ns < 0)
		return -1;

	/* Pin one with a file descriptor */
	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
		if (nsid->nd != &net_ns_desc)
			continue;

		if (nsid->type == NS_ROOT) {
			nsid->net.ns_fd = root_ns;
		} else {
			if (do_create_net_ns(nsid))
				goto err;
		}
	}

	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
		if (nsid->nd != &net_ns_desc)
			continue;

		if (switch_ns_by_fd(nsid->net.ns_fd, &net_ns_desc, NULL))
			goto err;

		if (prepare_net_ns_first_stage(nsid))
			goto err;

		nsid->net.nlsk = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
		if (nsid->net.nlsk < 0) {
			pr_perror("Can't create nlk socket");
			goto err;
		}

	}

	if (restore_links())
		goto err;

	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
		if (nsid->nd != &net_ns_desc)
			continue;

		if (switch_ns_by_fd(nsid->net.ns_fd, &net_ns_desc, NULL))
			goto err;

		if (prepare_net_ns_second_stage(nsid))
			goto err;

		close_safe(&nsid->net.nlsk);
	}

	close_service_fd(NS_FD_OFF);

	return 0;
err:
	return -1;
}


int prepare_net_namespaces(void)
{
	if (!(root_ns_mask & CLONE_NEWNET))
		return 0;

	return call_in_child_process(__prepare_net_namespaces, NULL);
}

static int do_restore_task_net_ns(struct ns_id *nsid, struct pstree_item *current)
{
	int fd;

	if (!(root_ns_mask & CLONE_NEWNET))
		return 0;

	fd = fdstore_get(nsid->net.nsfd_id);
	if (fd < 0)
		return -1;

	if (setns(fd, CLONE_NEWNET)) {
		pr_perror("Can't restore netns");
		close(fd);
		return -1;
	}
	close(fd);

	return 0;
}

int restore_task_net_ns(struct pstree_item *current)
{
	if (current->ids && current->ids->has_net_ns_id) {
		unsigned int id = current->ids->net_ns_id;
		struct ns_id *nsid;

		nsid = lookup_ns_by_id(id, &net_ns_desc);
		if (nsid == NULL) {
			pr_err("Can't find mount namespace %d\n", id);
			return -1;
		}

		BUG_ON(nsid->type == NS_CRIU);

		if (do_restore_task_net_ns(nsid, current))
			return -1;
	}

	return 0;
}

int netns_keep_nsfd(void)
{
	int ns_fd, ret;

	if (!(root_ns_mask & CLONE_NEWNET))
		return 0;

	/*
	 * When restoring a net namespace we need to communicate
	 * with the original (i.e. -- init) one. Thus, prepare for
	 * that before we leave the existing namespaces.
	 */

	ns_fd = __open_proc(PROC_SELF, 0, O_RDONLY | O_CLOEXEC, "ns/net");
	if (ns_fd < 0)
		return -1;

	ret = install_service_fd(NS_FD_OFF, ns_fd);
	if (ret < 0)
		pr_err("Can't install ns net reference\n");
	else
		pr_info("Saved netns fd for links restore\n");

	return ret >= 0 ? 0 : -1;
}

/*
 * If we want to modify iptables, we need to received the current
 * configuration, change it and load a new one into the kernel.
 * iptables can change or add only one rule.
 * iptables-restore allows to make a few changes for one iteration,
 * so it works faster.
 */
static int iptables_restore(bool ipv6, char *buf, int size)
{
	int pfd[2], ret = -1;
	char *cmd4[] = {"iptables-restore", "-w", "--noflush", NULL};
	char *cmd6[] = {"ip6tables-restore", "-w", "--noflush", NULL};
	char **cmd = ipv6 ? cmd6 : cmd4;

	if (pipe(pfd) < 0) {
		pr_perror("Unable to create pipe");
		return -1;
	}

	if (write(pfd[1], buf, size) < size) {
		pr_perror("Unable to write iptables configugration");
		goto err;
	}
	close_safe(&pfd[1]);

	ret = cr_system(pfd[0], -1, -1, cmd[0], cmd, 0);
err:
	close_safe(&pfd[1]);
	close_safe(&pfd[0]);
	return ret;
}

int network_lock_internal(void)
{
	char conf[] =	"*filter\n"
				":CRIU - [0:0]\n"
				"-I INPUT -j CRIU\n"
				"-I OUTPUT -j CRIU\n"
				"-A CRIU -m mark --mark " __stringify(SOCCR_MARK) " -j ACCEPT\n"
				"-A CRIU -j DROP\n"
				"COMMIT\n";
	int ret = 0, nsret;

	if (switch_ns(root_item->pid->real, &net_ns_desc, &nsret))
		return -1;


	ret |= iptables_restore(false, conf, sizeof(conf) - 1);
	if (kdat.ipv6)
		ret |= iptables_restore(true, conf, sizeof(conf) - 1);

	if (ret)
		pr_err("Locking network failed: iptables-restore returned %d. "
			"This may be connected to disabled "
			"CONFIG_NETFILTER_XT_MARK kernel build config "
			"option.\n", ret);

	if (restore_ns(nsret, &net_ns_desc))
		ret = -1;

	return ret;
}

static int network_unlock_internal(void)
{
	char conf[] =	"*filter\n"
			":CRIU - [0:0]\n"
			"-D INPUT -j CRIU\n"
			"-D OUTPUT -j CRIU\n"
			"-X CRIU\n"
			"COMMIT\n";
	int ret = 0, nsret;

	if (switch_ns(root_item->pid->real, &net_ns_desc, &nsret))
		return -1;


	ret |= iptables_restore(false, conf, sizeof(conf) - 1);
	if (kdat.ipv6)
		ret |= iptables_restore(true, conf, sizeof(conf) - 1);

	if (restore_ns(nsret, &net_ns_desc))
		ret = -1;

	return ret;
}

int network_lock(void)
{
	pr_info("Lock network\n");

	/* Each connection will be locked on dump */
	if  (!(root_ns_mask & CLONE_NEWNET))
		return 0;

	if (run_scripts(ACT_NET_LOCK))
		return -1;

	return network_lock_internal();
}

void network_unlock(void)
{
	pr_info("Unlock network\n");

	cpt_unlock_tcp_connections();
	rst_unlock_tcp_connections();

	if (root_ns_mask & CLONE_NEWNET) {
		run_scripts(ACT_NET_UNLOCK);
		network_unlock_internal();
	}
}

int veth_pair_add(char *in, char *out)
{
	char *e_str;

	e_str = xmalloc(200); /* For 3 IFNAMSIZ + 8 service characters */
	if (!e_str)
		return -1;
	snprintf(e_str, 200, "veth[%s]:%s", in, out);
	return add_external(e_str);
}

int macvlan_ext_add(struct external *ext)
{
	ext->data = (void *) (unsigned long) if_nametoindex(external_val(ext));
	if (ext->data == 0) {
		pr_perror("can't get ifindex of %s", ext->id);
		return -1;
	}

	return 0;
}

/*
 * The setns() syscall (called by switch_ns()) can be extremely
 * slow. If we call it two or more times from the same task the
 * kernel will synchonously go on a very slow routine called
 * synchronize_rcu() trying to put a reference on old namespaces.
 *
 * To avoid doing this more than once we pre-create all the
 * needed other-ns sockets in advance.
 */

static int prep_ns_sockets(struct ns_id *ns, bool for_dump)
{
	int nsret = -1, ret;
#ifdef CONFIG_HAS_SELINUX
	security_context_t ctx;
#endif

	if (ns->type != NS_CRIU) {
		pr_info("Switching to %d's net for collecting sockets\n", ns->ns_pid);
		if (switch_ns(ns->ns_pid, &net_ns_desc, &nsret))
			return -1;
	}

	if (for_dump) {
		ret = ns->net.nlsk = socket(PF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
		if (ret < 0) {
			pr_perror("Can't create sock diag socket");
			goto err_nl;
		}
	} else
		ns->net.nlsk = -1;

#ifdef CONFIG_HAS_SELINUX
	/*
	 * If running on a system with SELinux enabled the socket for the
	 * communication between parasite daemon and the main
	 * CRIU process needs to be correctly labeled.
	 * Initially this was motivated by Podman's use case: The container
	 * is usually running as something like '...:...:container_t:...:....'
	 * and CRIU started from runc and Podman will run as
	 * '...:...:container_runtime_t:...:...'. As the parasite will be
	 * running with the same context as the container process: 'container_t'.
	 * Allowing a container process to connect via socket to the outside
	 * of the container ('container_runtime_t') is not desired and
	 * therefore CRIU needs to label the socket with the context of
	 * the container: 'container_t'.
	 * So this first gets the context of the root container process
	 * and tells SELinux to label the next created socket with
	 * the same label as the root container process.
	 * For this to work it is necessary to have the correct SELinux
	 * policies installed. For Fedora based systems this is part
	 * of the container-selinux package.
	 */

	/*
	 * This assumes that all processes CRIU wants to dump are labeled
	 * with the same SELinux context. If some of the child processes
	 * have different labels this will not work and needs additional
	 * SELinux policies. But the whole SELinux socket labeling relies
	 * on the correct SELinux being available.
	 */
	if (kdat.lsm == LSMTYPE__SELINUX) {
		ret = getpidcon_raw(root_item->pid->real, &ctx);
		if (ret < 0) {
			pr_perror("Getting SELinux context for PID %d failed",
				  root_item->pid->real);
			goto err_sq;
		}

		ret = setsockcreatecon(ctx);
		freecon(ctx);
		if (ret < 0) {
			pr_perror("Setting SELinux socket context for PID %d failed",
				  root_item->pid->real);
			goto err_sq;
		}
	}
#endif

	ret = ns->net.seqsk = socket(PF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0);
	if (ret < 0) {
		pr_perror("Can't create seqsk for parasite");
		goto err_sq;
	}

	ret = 0;

#ifdef CONFIG_HAS_SELINUX
	/*
	 * Once the socket has been created, reset the SELinux socket labelling
	 * back to the default value of this process.
	 */
	if (kdat.lsm == LSMTYPE__SELINUX) {
		ret = setsockcreatecon_raw(NULL);
		if (ret < 0) {
			pr_perror("Resetting SELinux socket context to "
				  "default for PID %d failed",
				  root_item->pid->real);
			goto err_ret;
		}
	}
#endif

out:
	if (nsret >= 0 && restore_ns(nsret, &net_ns_desc) < 0) {
		nsret = -1;
		if (ret == 0)
			goto err_ret;
	}

	return ret;

err_ret:
	close(ns->net.seqsk);
err_sq:
	if (ns->net.nlsk >= 0)
		close(ns->net.nlsk);
err_nl:
	goto out;
}

static int netns_nr;
static int collect_net_ns(struct ns_id *ns, void *oarg)
{
	bool for_dump = (oarg == (void *)1);
	char id[64], *val;
	int ret;

	pr_info("Collecting netns %d/%d\n", ns->id, ns->ns_pid);

	snprintf(id, sizeof(id), "net[%u]", ns->kid);
	val = external_lookup_by_key(id);
	if (!IS_ERR_OR_NULL(val)) {
		pr_debug("The %s netns is external\n", id);
		ns->ext_key = val;
	}

	ret = prep_ns_sockets(ns, for_dump);
	if (ret)
		return ret;

	netns_nr++;

	if (!for_dump)
		return 0;

	return collect_sockets(ns);
}

int collect_net_namespaces(bool for_dump)
{
	return walk_namespaces(&net_ns_desc, collect_net_ns,
			(void *)(for_dump ? 1UL : 0));
}

struct ns_desc net_ns_desc = NS_DESC_ENTRY(CLONE_NEWNET, "net");

struct ns_id *net_get_root_ns()
{
	static struct ns_id *root_netns = NULL;

	if (root_netns)
		return root_netns;

	if (root_item->ids == NULL)
		return NULL;

	root_netns = lookup_ns_by_id(root_item->ids->net_ns_id, &net_ns_desc);

	return root_netns;
}

/*
 * socket_diag doesn't report unbound and unconnected sockets,
 * so we have to get their network namesapces explicitly
 */
struct ns_id *get_socket_ns(int lfd)
{
	struct ns_id *ns;
	struct stat st;
	int ns_fd;

	ns_fd = ioctl(lfd, SIOCGSKNS);
	if (ns_fd < 0) {
		/* backward compatibility with old kernels */
		if (netns_nr == 1)
			return net_get_root_ns();

		pr_perror("Unable to get a socket net namespace");
		return NULL;
	}
	if (fstat(ns_fd, &st)) {
		pr_perror("Unable to stat a network namespace");
		close(ns_fd);
		return NULL;
	}
	close(ns_fd);

	ns = lookup_ns_by_kid(st.st_ino, &net_ns_desc);
	if (ns == NULL) {
		pr_err("Unable to dump a socket from an external network namespace\n");
		return NULL;
	}

	return ns;
}

void check_has_netns_ioc(int fd, bool *kdat_val, const char *name)
{
	int ns_fd;

	ns_fd = ioctl(fd, SIOCGSKNS);
	*kdat_val = (ns_fd >= 0);

	if (ns_fd < 0)
		pr_warn("Unable to get %s network namespace\n", name);
	else
		close(ns_fd);
}

int kerndat_socket_netns(void)
{
	int sk;

	sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0) {
		pr_perror("Unable to create socket");
		return -1;
	}
	check_has_netns_ioc(sk, &kdat.sk_ns, "socket");
	close(sk);

	return 0;
}

static int move_to_bridge(struct external *ext, void *arg)
{
	int s = *(int *)arg;
	int ret;
	char *out, *br;
	struct ifreq ifr;

	out = external_val(ext);
	if (!out)
		return -1;

	br = strchr(out, '@');
	if (!br)
		return 0;

	*br = '\0';
	br++;

	{
		pr_debug("\tMoving dev %s to bridge %s\n", out, br);

		if (s == -1) {
			s = socket(AF_LOCAL, SOCK_STREAM|SOCK_CLOEXEC, 0);
			if (s < 0) {
				pr_perror("Can't create control socket");
				return -1;
			}
		}

		/*
		 * Add the device to the bridge. This is equivalent to:
		 * $ brctl addif <bridge> <device>
		 */
		ifr.ifr_ifindex = if_nametoindex(out);
		if (ifr.ifr_ifindex == 0) {
			pr_perror("Can't get index of %s", out);
			ret = -1;
			goto out;
		}
		strlcpy(ifr.ifr_name, br, IFNAMSIZ);
		ret = ioctl(s, SIOCBRADDIF, &ifr);
		if (ret < 0) {
			pr_perror("Can't add interface %s to bridge %s", out, br);
			goto out;
		}

		/*
		 * Make sure the device is up.  This is equivalent to:
		 * $ ip link set dev <device> up
		 */
		ifr.ifr_ifindex = 0;
		strlcpy(ifr.ifr_name, out, IFNAMSIZ);
		ret = ioctl(s, SIOCGIFFLAGS, &ifr);
		if (ret < 0) {
			pr_perror("Can't get flags of interface %s", out);
			goto out;
		}

		ret = 0;
		if (ifr.ifr_flags & IFF_UP)
			goto out;

		ifr.ifr_flags |= IFF_UP;
		if (changeflags(s, out, ifr.ifr_flags) < 0)
			goto out;
		ret = 0;
	}
out:
	br--;
	*br = '@';
	*(int *)arg = s;
	return ret;
}

int move_veth_to_bridge(void)
{
	int sk = -1, ret;

	ret = external_for_each_type("veth", move_to_bridge, &sk);
	if (sk >= 0)
		close(sk);

	return ret;
}

#if NLA_TYPE_MAX < 14
#define NLA_S32 14
#endif

#ifndef NETNSA_MAX
/* Attributes of RTM_NEWNSID/RTM_GETNSID messages */
enum {
	NETNSA_NONE,
#define NETNSA_NSID_NOT_ASSIGNED -1
	NETNSA_NSID,
	NETNSA_PID,
	NETNSA_FD,
	__NETNSA_MAX,
};

#define NETNSA_MAX		(__NETNSA_MAX - 1)
#endif

static struct nla_policy rtnl_net_policy[NETNSA_MAX + 1] = {
	[NETNSA_NONE]		= { .type = NLA_UNSPEC },
	[NETNSA_NSID]		= { .type = NLA_S32 },
	[NETNSA_PID]		= { .type = NLA_U32 },
	[NETNSA_FD]		= { .type = NLA_U32 },
};

static int nsid_cb(struct nlmsghdr *msg, struct ns_id *ns, void *arg)
{
	struct nlattr *tb[NETNSA_MAX + 1];
	int err;

	err = nlmsg_parse(msg, sizeof(struct rtgenmsg), tb,
				NETNSA_MAX, rtnl_net_policy);
	if (err < 0)
		return NL_STOP;

	if (tb[NETNSA_NSID])
		*((int *)arg) = nla_get_s32(tb[NETNSA_NSID]);

	return 0;
}

static int net_set_nsid(int rtsk, int fd, int nsid)
{
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
		char msg[128];
	} req;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
	req.nlh.nlmsg_type = RTM_NEWNSID;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nlh.nlmsg_seq = CR_NLMSG_SEQ;
	if (addattr_l(&req.nlh, sizeof(req), NETNSA_FD, &fd, sizeof(fd)))
		return -1;
	if (addattr_l(&req.nlh, sizeof(req), NETNSA_NSID, &nsid, sizeof(nsid)))
		return -1;

	if (do_rtnl_req(rtsk, &req, req.nlh.nlmsg_len, NULL, NULL, NULL, NULL) < 0)
		return -1;

	return 0;
}

int net_get_nsid(int rtsk, int pid, int *nsid)
{
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
		char msg[128];
	} req;
	int32_t id = INT_MIN;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
	req.nlh.nlmsg_type = RTM_GETNSID;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nlh.nlmsg_seq = CR_NLMSG_SEQ;
	if (addattr_l(&req.nlh, sizeof(req), NETNSA_PID, &pid, sizeof(pid)))
		return -1;

	if (do_rtnl_req(rtsk, &req, req.nlh.nlmsg_len, nsid_cb, NULL, NULL, (void *) &id) < 0)
		return -1;

	if (id == INT_MIN)
		return -1;

	*nsid = id;

	return 0;
}


static int nsid_link_info(struct ns_id *ns, struct net_link *link, struct newlink_req *req)
{
	NetDeviceEntry *nde = link->nde;
	struct rtattr *veth_data, *peer_data;
	struct ifinfomsg ifm;

	addattr_l(&req->h, sizeof(*req), IFLA_INFO_KIND, "veth", 4);

	veth_data = NLMSG_TAIL(&req->h);
	addattr_l(&req->h, sizeof(*req), IFLA_INFO_DATA, NULL, 0);
	peer_data = NLMSG_TAIL(&req->h);
	memset(&ifm, 0, sizeof(ifm));

	ifm.ifi_index = nde->peer_ifindex;
	addattr_l(&req->h, sizeof(*req), VETH_INFO_PEER, &ifm, sizeof(ifm));

	addattr_l(&req->h, sizeof(*req), IFLA_NET_NS_FD, &nde->peer_nsid, sizeof(int));
	peer_data->rta_len = (void *)NLMSG_TAIL(&req->h) - (void *)peer_data;
	veth_data->rta_len = (void *)NLMSG_TAIL(&req->h) - (void *)veth_data;

	return 0;
}

static int check_one_link_nsid(struct nlmsghdr *hdr, struct ns_id *ns, void *arg)
{
	bool *has_link_nsid = arg;
	struct ifinfomsg *ifi;
	int len = hdr->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
	struct nlattr *tb[IFLA_MAX + 1];

	ifi = NLMSG_DATA(hdr);

	if (len < 0) {
		pr_err("No iflas for link %d\n", ifi->ifi_index);
		return -1;
	}

	nlmsg_parse(hdr, sizeof(struct ifinfomsg), tb, IFLA_MAX, NULL);
	pr_info("\tLD: Got link %d, type %d\n", ifi->ifi_index, ifi->ifi_type);

	if (tb[IFLA_LINK_NETNSID])
		*has_link_nsid = true;

	return 0;
}

static int check_link_nsid(int rtsk, void *args)
{
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;

	pr_info("Dumping netns links\n");

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = RTM_GETLINK;
	req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = CR_NLMSG_SEQ;
	req.g.rtgen_family = AF_PACKET;

	return do_rtnl_req(rtsk, &req, sizeof(req), check_one_link_nsid, NULL, NULL, args);
}

int kerndat_link_nsid(void)
{
	int status;
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		pr_perror("Unable to fork a process");
		return -1;
	}

	if (pid == 0) {
		bool has_link_nsid;
		NetDeviceEntry nde = NET_DEVICE_ENTRY__INIT;
		struct net_link link = {
			.created = false,
			.nde = &nde,
		};
		int nsfd, sk, ret;

		if (unshare(CLONE_NEWNET)) {
			pr_perror("Unable create a network namespace");
			exit(1);
		}

		nsfd = open_proc(PROC_SELF, "ns/net");
		if (nsfd < 0)
			exit(1);

		if (unshare(CLONE_NEWNET)) {
			pr_perror("Unable create a network namespace");
			exit(1);
		}

		sk = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
		if (sk < 0) {
			pr_perror("Unable to create a netlink socket");
			exit(1);
		}

		nde.type = ND_TYPE__VETH;
		nde.name = "veth";
		nde.ifindex = 10;
		nde.mtu = 1500;
		nde.peer_nsid = nsfd;
		nde.peer_ifindex = 11;
		nde.has_peer_ifindex = true;
		nde.has_peer_nsid = true;

		ret = restore_one_link(NULL, &link, sk, nsid_link_info, NULL);
		if (ret) {
			pr_err("Unable to create a veth pair: %d\n", ret);
			exit(1);
		}

		has_link_nsid = false;
		if (check_link_nsid(sk, &has_link_nsid))
			exit(1);

		if (!has_link_nsid)
			exit(5);

		close(sk);

		exit(0);
	}

	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("Unable to wait a process");
		return -1;
	}

	if (status) {
		pr_warn("NSID isn't reported for network links\n");
		return 0;
	}

	kdat.has_link_nsid = true;

	return 0;
}
