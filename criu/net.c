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
#include <net/if.h>
#include <linux/sockios.h>
#include <libnl3/netlink/msg.h>

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

#include "protobuf.h"
#include "images/netdev.pb-c.h"

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

static char *devconfs[] = {
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
};

/*
 * I case if some entry is missing in
 * the kernel, simply write DEVCONFS_UNUSED
 * into the image so we would skip it.
 */
#define DEVCONFS_UNUSED        (-1u)

#define NET_CONF_PATH "net/ipv4/conf"
#define MAX_CONF_OPT_PATH IFNAMSIZ+50

static int ipv4_conf_op(char *tgt, int *conf, int n, int op, NetnsEntry **netns)
{
	int i, ri;
	int ret, flags = op == CTL_READ ? CTL_FLAGS_OPTIONAL : 0;
	struct sysctl_req req[ARRAY_SIZE(devconfs)];
	char path[ARRAY_SIZE(devconfs)][MAX_CONF_OPT_PATH];

	if (n > ARRAY_SIZE(devconfs))
		pr_warn("The image contains unknown sysctl-s\n");

	for (i = 0, ri = 0; i < ARRAY_SIZE(devconfs); i++) {
		if (i >= n) {
			pr_warn("Skip %s/%s\n", tgt, devconfs[i]);
			continue;
		}
		/*
		 * If dev conf value is the same as default skip restoring it
		 */
		if (netns && conf[i] == (*netns)->def_conf[i]) {
			pr_debug("DEBUG Skip %s/%s, val =%d\n", tgt, devconfs[i], conf[i]);
			continue;
		}

		if (op == CTL_WRITE && conf[i] == DEVCONFS_UNUSED)
			continue;
		else if (op == CTL_READ)
			conf[i] = DEVCONFS_UNUSED;

		snprintf(path[i], MAX_CONF_OPT_PATH, "%s/%s/%s", NET_CONF_PATH, tgt, devconfs[i]);
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

int write_netdev_img(NetDeviceEntry *nde, struct cr_imgset *fds)
{
	return pb_write_one(img_from_set(fds, CR_FD_NETDEV), nde, PB_NETDEV);
}

static int dump_one_netdev(int type, struct ifinfomsg *ifi,
		struct nlattr **tb, struct cr_imgset *fds,
		int (*dump)(NetDeviceEntry *, struct cr_imgset *))
{
	int ret;
	NetDeviceEntry netdev = NET_DEVICE_ENTRY__INIT;

	if (!tb[IFLA_IFNAME]) {
		pr_err("No name for link %d\n", ifi->ifi_index);
		return -1;
	}

	netdev.type = type;
	netdev.ifindex = ifi->ifi_index;
	netdev.mtu = *(int *)RTA_DATA(tb[IFLA_MTU]);
	netdev.flags = ifi->ifi_flags;
	netdev.name = RTA_DATA(tb[IFLA_IFNAME]);

	if (tb[IFLA_ADDRESS] && (type != ND_TYPE__LOOPBACK)) {
		netdev.has_address = true;
		netdev.address.data = nla_data(tb[IFLA_ADDRESS]);
		netdev.address.len = nla_len(tb[IFLA_ADDRESS]);
		pr_info("Found ll addr (%02x:../%d) for %s\n",
				(int)netdev.address.data[0],
				(int)netdev.address.len, netdev.name);
	}

	netdev.n_conf = ARRAY_SIZE(devconfs);
	netdev.conf = xmalloc(sizeof(int) * netdev.n_conf);
	if (!netdev.conf)
		return -1;

	ret = ipv4_conf_op(netdev.name, netdev.conf, netdev.n_conf, CTL_READ, NULL);
	if (ret < 0)
		goto err_free;

	if (!dump)
		dump = write_netdev_img;

	ret = dump(&netdev, fds);
err_free:
	xfree(netdev.conf);
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
		struct nlattr **tb, struct cr_imgset *fds)
{
	int ret;

	ret = run_plugins(DUMP_EXT_LINK, ifi->ifi_index, ifi->ifi_type, kind);
	if (ret == 0)
		return dump_one_netdev(ND_TYPE__EXTLINK, ifi, tb, fds, NULL);

	if (ret == -ENOTSUP)
		pr_err("Unsupported link %d (type %d kind %s)\n",
				ifi->ifi_index, ifi->ifi_type, kind);
	return -1;
}

static int dump_bridge(NetDeviceEntry *nde, struct cr_imgset *imgset)
{
	char spath[IFNAMSIZ + 16]; /* len("class/net//brif") + 1 for null */
	int ret, fd;

	ret = snprintf(spath, sizeof(spath), "class/net/%s/brif", nde->name);
	if (ret < 0 || ret >= sizeof(spath))
		return -1;

	/* Let's only allow dumping empty bridges for now. To do a full bridge
	 * restore, we need to make sure the bridge and slaves are restored in
	 * the right order and attached correctly. It looks like the veth code
	 * supports this, but we need some way to do ordering.
	 */
	fd = openat(ns_sysfs_fd, spath, O_DIRECTORY, 0);
	if (fd < 0) {
		pr_perror("opening %s failed", spath);
		return -1;
	}

	ret = is_empty_dir(fd);
	close(fd);
	if (ret < 0) {
		pr_perror("problem testing %s for emptiness", spath);
		return -1;
	}

	if (!ret) {
		pr_err("dumping bridges with attached slaves not supported currently\n");
		return -1;
	}

	return write_netdev_img(nde, imgset);
}

static int dump_one_ethernet(struct ifinfomsg *ifi, char *kind,
		struct nlattr **tb, struct cr_imgset *fds)
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
		return dump_one_netdev(ND_TYPE__VETH, ifi, tb, fds, NULL);
	if (!strcmp(kind, "tun"))
		return dump_one_netdev(ND_TYPE__TUN, ifi, tb, fds, dump_tun_link);
	if (!strcmp(kind, "bridge"))
		return dump_one_netdev(ND_TYPE__BRIDGE, ifi, tb, fds, dump_bridge);
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

	return dump_unknown_device(ifi, kind, tb, fds);
}

static int dump_one_gendev(struct ifinfomsg *ifi, char *kind,
		struct nlattr **tb, struct cr_imgset *fds)
{
	if (!strcmp(kind, "tun"))
		return dump_one_netdev(ND_TYPE__TUN, ifi, tb, fds, dump_tun_link);

	return dump_unknown_device(ifi, kind, tb, fds);
}

static int dump_one_voiddev(struct ifinfomsg *ifi, char *kind,
		struct nlattr **tb, struct cr_imgset *fds)
{
	if (!strcmp(kind, "venet"))
		return dump_one_netdev(ND_TYPE__VENET, ifi, tb, fds, NULL);

	return dump_unknown_device(ifi, kind, tb, fds);
}

static int dump_one_gre(struct ifinfomsg *ifi, char *kind,
		struct nlattr **tb, struct cr_imgset *fds)
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

	return dump_unknown_device(ifi, kind, tb, fds);
}

static int dump_one_link(struct nlmsghdr *hdr, void *arg)
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
		return dump_one_netdev(ND_TYPE__LOOPBACK, ifi, tb, fds, NULL);

	kind = link_kind(ifi, tb);
	if (!kind)
		goto unk;

	switch (ifi->ifi_type) {
	case ARPHRD_ETHER:
		ret = dump_one_ethernet(ifi, kind, tb, fds);
		break;
	case ARPHRD_NONE:
		ret = dump_one_gendev(ifi, kind, tb, fds);
		break;
	case ARPHRD_VOID:
		ret = dump_one_voiddev(ifi, kind, tb, fds);
		break;
	case ARPHRD_IPGRE:
		ret = dump_one_gre(ifi, kind, tb, fds);
		break;
	default:
unk:
		ret = dump_unknown_device(ifi, kind, tb, fds);
		break;
	}

	return ret;
}

static int dump_one_nf(struct nlmsghdr *hdr, void *arg)
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
		ret = do_rtnl_req(sk, nlh, nlh->nlmsg_len, NULL, NULL, NULL);
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

	ret = do_rtnl_req(sk, &req, sizeof(req), dump_one_nf, NULL, img);
	close(sk);
out:
	return ret;

}

static int dump_links(struct cr_imgset *fds)
{
	int sk, ret;
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;

	pr_info("Dumping netns links\n");

	ret = sk = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sk < 0) {
		pr_perror("Can't open rtnl sock for net dump");
		goto out;
	}

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = RTM_GETLINK;
	req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = CR_NLMSG_SEQ;
	req.g.rtgen_family = AF_PACKET;

	ret = do_rtnl_req(sk, &req, sizeof(req), dump_one_link, NULL, fds);
	close(sk);
out:
	return ret;
}

static int restore_link_cb(struct nlmsghdr *hdr, void *arg)
{
	pr_info("Got response on SETLINK =)\n");
	return 0;
}

struct newlink_req {
	struct nlmsghdr h;
	struct ifinfomsg i;
	char buf[1024];
};

static int do_rtm_link_req(int msg_type, NetDeviceEntry *nde, int nlsk,
		int (*link_info)(NetDeviceEntry *, struct newlink_req *))
{
	struct newlink_req req;

	memset(&req, 0, sizeof(req));

	req.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.h.nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE;
	req.h.nlmsg_type = msg_type;
	req.h.nlmsg_seq = CR_NLMSG_SEQ;
	req.i.ifi_family = AF_PACKET;
	/*
	 * SETLINK is called for external devices which may
	 * have ifindex changed. Thus configure them by their
	 * name only.
	 */
	if (msg_type == RTM_NEWLINK)
		req.i.ifi_index = nde->ifindex;
	req.i.ifi_flags = nde->flags;

	addattr_l(&req.h, sizeof(req), IFLA_IFNAME, nde->name, strlen(nde->name));
	addattr_l(&req.h, sizeof(req), IFLA_MTU, &nde->mtu, sizeof(nde->mtu));

	if (nde->has_address) {
		pr_debug("Restore ll addr (%02x:../%d) for device\n",
				(int)nde->address.data[0], (int)nde->address.len);
		addattr_l(&req.h, sizeof(req), IFLA_ADDRESS,
				nde->address.data, nde->address.len);
	}

	if (link_info) {
		struct rtattr *linkinfo;
		int ret;

		linkinfo = NLMSG_TAIL(&req.h);
		addattr_l(&req.h, sizeof(req), IFLA_LINKINFO, NULL, 0);

		ret = link_info(nde, &req);
		if (ret < 0)
			return ret;

		linkinfo->rta_len = (void *)NLMSG_TAIL(&req.h) - (void *)linkinfo;
	}

	return do_rtnl_req(nlsk, &req, req.h.nlmsg_len, restore_link_cb, NULL, NULL);
}

int restore_link_parms(NetDeviceEntry *nde, int nlsk)
{
	return do_rtm_link_req(RTM_SETLINK, nde, nlsk, NULL);
}

static int restore_one_link(NetDeviceEntry *nde, int nlsk,
		int (*link_info)(NetDeviceEntry *, struct newlink_req *))
{
	pr_info("Restoring netdev %s idx %d\n", nde->name, nde->ifindex);
	return do_rtm_link_req(RTM_NEWLINK, nde, nlsk, link_info);
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

static int veth_link_info(NetDeviceEntry *nde, struct newlink_req *req)
{
	int ns_fd = get_service_fd(NS_FD_OFF);
	struct rtattr *veth_data, *peer_data;
	struct ifinfomsg ifm;
	struct veth_pair *n;

	BUG_ON(ns_fd < 0);

	addattr_l(&req->h, sizeof(*req), IFLA_INFO_KIND, "veth", 4);

	veth_data = NLMSG_TAIL(&req->h);
	addattr_l(&req->h, sizeof(*req), IFLA_INFO_DATA, NULL, 0);
	peer_data = NLMSG_TAIL(&req->h);
	memset(&ifm, 0, sizeof(ifm));
	addattr_l(&req->h, sizeof(*req), VETH_INFO_PEER, &ifm, sizeof(ifm));
	list_for_each_entry(n, &opts.veth_pairs, node) {
		if (!strcmp(nde->name, n->inside))
			break;
	}
	if (&n->node != &opts.veth_pairs)
		addattr_l(&req->h, sizeof(*req), IFLA_IFNAME, n->outside, strlen(n->outside));
	addattr_l(&req->h, sizeof(*req), IFLA_NET_NS_FD, &ns_fd, sizeof(ns_fd));
	peer_data->rta_len = (void *)NLMSG_TAIL(&req->h) - (void *)peer_data;
	veth_data->rta_len = (void *)NLMSG_TAIL(&req->h) - (void *)veth_data;

	return 0;
}

static int venet_link_info(NetDeviceEntry *nde, struct newlink_req *req)
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

static int bridge_link_info(NetDeviceEntry *nde, struct newlink_req *req)
{
	struct rtattr *bridge_data;

	bridge_data = NLMSG_TAIL(&req->h);
	addattr_l(&req->h, sizeof(*req), IFLA_INFO_KIND, "bridge", sizeof("bridge"));
	bridge_data->rta_len = (void *)NLMSG_TAIL(&req->h) - (void *)bridge_data;

	return 0;
}

static int restore_link(NetDeviceEntry *nde, int nlsk)
{
	pr_info("Restoring link %s type %d\n", nde->name, nde->type);

	switch (nde->type) {
	case ND_TYPE__LOOPBACK: /* fallthrough */
	case ND_TYPE__EXTLINK:  /* see comment in images/netdev.proto */
		return restore_link_parms(nde, nlsk);
	case ND_TYPE__VENET:
		return restore_one_link(nde, nlsk, venet_link_info);
	case ND_TYPE__VETH:
		return restore_one_link(nde, nlsk, veth_link_info);
	case ND_TYPE__TUN:
		return restore_one_tun(nde, nlsk);
	case ND_TYPE__BRIDGE:
		return restore_one_link(nde, nlsk, bridge_link_info);

	default:
		pr_err("Unsupported link type %d\n", nde->type);
		break;
	}

	return -1;
}

static int restore_links(int pid, NetnsEntry **netns)
{
	int nlsk, ret;
	struct cr_img *img;
	NetDeviceEntry *nde;

	img = open_image(CR_FD_NETDEV, O_RSTR, pid);
	if (!img)
		return -1;

	nlsk = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nlsk < 0) {
		pr_perror("Can't create nlk socket");
		close_image(img);
		return -1;
	}

	while (1) {
		ret = pb_read_one_eof(img, &nde, PB_NETDEV);
		if (ret <= 0)
			break;

		ret = restore_link(nde, nlsk);
		if (ret) {
			pr_err("Can't restore link\n");
			goto exit;
		}

		if (nde->conf) {
			NetnsEntry **def_netns = netns;
			/*
			 * optimize restore of devices configuration except lo
			 * lo is created with namespace and before default is set
			 * so we cant optimize its restore
			 */
			if (nde->type == ND_TYPE__LOOPBACK)
				def_netns = NULL;
			ret = ipv4_conf_op(nde->name, nde->conf, nde->n_conf, CTL_WRITE, def_netns);
		}
exit:
		net_device_entry__free_unpacked(nde, NULL);
		if (ret)
			break;
	}

	close(nlsk);
	close_image(img);
	return ret;
}

static int run_ip_tool(char *arg1, char *arg2, char *arg3, int fdin, int fdout, unsigned flags)
{
	char *ip_tool_cmd;
	int ret;

	pr_debug("\tRunning ip %s %s\n", arg1, arg2);

	ip_tool_cmd = getenv("CR_IP_TOOL");
	if (!ip_tool_cmd)
		ip_tool_cmd = "ip";

	ret = cr_system(fdin, fdout, -1, ip_tool_cmd,
				(char *[]) { "ip", arg1, arg2, arg3, NULL }, flags);
	if (ret) {
		if (!(flags & CRS_CAN_FAIL))
			pr_err("IP tool failed on %s %s\n", arg1, arg2);
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
	return run_ip_tool("addr", "save", NULL, -1, img_raw_fd(img), 0);
}

static inline int dump_route(struct cr_imgset *fds)
{
	struct cr_img *img;

	img = img_from_set(fds, CR_FD_ROUTE);
	if (run_ip_tool("route", "save", NULL, -1, img_raw_fd(img), 0))
		return -1;

	/* If ipv6 is disabled, "ip -6 route dump" dumps all routes */
	if (!kdat.ipv6)
		return 0;

	img = img_from_set(fds, CR_FD_ROUTE6);
	if (run_ip_tool("-6", "route", "save", -1, img_raw_fd(img), 0))
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

	if (run_ip_tool("rule", "save", NULL, -1, img_raw_fd(img), CRS_CAN_FAIL)) {
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

static int dump_netns_conf(struct cr_imgset *fds)
{
	int ret, n;
	NetnsEntry netns = NETNS_ENTRY__INIT;

	netns.n_def_conf = ARRAY_SIZE(devconfs);
	netns.n_all_conf = ARRAY_SIZE(devconfs);
	netns.def_conf = xmalloc(sizeof(int) * netns.n_def_conf);
	if (!netns.def_conf)
		return -1;
	netns.all_conf = xmalloc(sizeof(int) * netns.n_all_conf);
	if (!netns.all_conf) {
		xfree(netns.def_conf);
		return -1;
	}

	n = netns.n_def_conf;
	ret = ipv4_conf_op("default", netns.def_conf, n, CTL_READ, NULL);
	if (ret < 0)
		goto err_free;
	ret = ipv4_conf_op("all", netns.all_conf, n, CTL_READ, NULL);
	if (ret < 0)
		goto err_free;

	ret = pb_write_one(img_from_set(fds, CR_FD_NETNS), &netns, PB_NETNS);
err_free:
	xfree(netns.def_conf);
	xfree(netns.all_conf);
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
		ret = run_ip_tool(cmd, "restore", NULL, img_raw_fd(img), -1, 0);
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
	run_ip_tool("rule", "delete", NULL, -1, -1, 0);
	run_ip_tool("rule", "delete", NULL, -1, -1, 0);
	run_ip_tool("rule", "delete", NULL, -1, -1, 0);

	if (restore_ip_dump(CR_FD_RULE, pid, "rule"))
		ret = -1;
close:
	close_image(img);
out:
	return ret;
}

static inline int restore_iptables(int pid)
{
	int ret = -1;
	struct cr_img *img;

	img = open_image(CR_FD_IPTABLES, O_RSTR, pid);
	if (img) {
		ret = run_iptables_tool("iptables-restore", img_raw_fd(img), -1);
		close_image(img);
	}
	if (ret)
		return ret;

	img = open_image(CR_FD_IP6TABLES, O_RSTR, pid);
	if (img == NULL)
		return -1;
	if (empty_image(img))
		goto out;

	ret = run_iptables_tool("ip6tables-restore", img_raw_fd(img), -1);
out:
	close_image(img);

	return ret;
}

static int restore_netns_conf(int pid, NetnsEntry **netns)
{
	int ret = 0, n;
	struct cr_img *img;

	img = open_image(CR_FD_NETNS, O_RSTR, pid);
	if (!img)
		return -1;

	if (empty_image(img))
		/* Backward compatibility */
		goto out;

	ret = pb_read_one(img, netns, PB_NETNS);
	if (ret < 0) {
		pr_err("Can not read netns object\n");
		return -1;
	}

	n = (*netns)->n_def_conf;
	ret = ipv4_conf_op("default", (*netns)->def_conf, n, CTL_WRITE, NULL);
	if (ret)
		goto out;
	ret = ipv4_conf_op("all", (*netns)->all_conf, n, CTL_WRITE, NULL);
out:
	close_image(img);
	return ret;
}

static int mount_ns_sysfs(void)
{
	char sys_mount[] = "crtools-sys.XXXXXX";

	BUG_ON(ns_sysfs_fd != -1);

	/*
	 * A new mntns is required to avoid the race between
	 * open_detach_mount and creating mntns.
	 */
	if (unshare(CLONE_NEWNS)) {
		pr_perror("Can't create new mount namespace");
		return -1;
	}

	if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL)) {
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

int dump_net_ns(int ns_id)
{
	struct cr_imgset *fds;
	int ret;

	fds = cr_imgset_open(ns_id, NETNS, O_DUMP);
	if (fds == NULL)
		return -1;

	ret = mount_ns_sysfs();
	if (!(opts.empty_ns & CLONE_NEWNET)) {
		if (!ret)
			ret = dump_netns_conf(fds);
		if (!ret)
			ret = dump_links(fds);
		if (!ret)
			ret = dump_ifaddr(fds);
		if (!ret)
			ret = dump_route(fds);
		if (!ret)
			ret = dump_rule(fds);
	}
	if (!ret)
		ret = dump_iptables(fds);
	if (!ret)
		ret = dump_nf_ct(fds, CR_FD_NETNF_CT);
	if (!ret)
		ret = dump_nf_ct(fds, CR_FD_NETNF_EXP);

	close(ns_sysfs_fd);
	ns_sysfs_fd = -1;

	close_cr_imgset(&fds);
	return ret;
}

int prepare_net_ns(int pid)
{
	int ret = 0;
	NetnsEntry *netns = NULL;

	if (!(opts.empty_ns & CLONE_NEWNET)) {
		ret = restore_netns_conf(pid, &netns);
		if (!ret)
			ret = restore_links(pid, &netns);
		if (netns)
			netns_entry__free_unpacked(netns, NULL);

		if (!ret)
			ret = restore_ifaddr(pid);
		if (!ret)
			ret = restore_route(pid);
		if (!ret)
			ret = restore_rule(pid);
	}
	if (!ret)
		ret = restore_iptables(pid);
	if (!ret)
		ret = restore_nf_ct(pid, CR_FD_NETNF_CT);
	if (!ret)
		ret = restore_nf_ct(pid, CR_FD_NETNF_EXP);

	close_service_fd(NS_FD_OFF);

	return ret;
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

	ns_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (ns_fd < 0) {
		pr_perror("Can't cache net fd");
		return -1;
	}

	ret = install_service_fd(NS_FD_OFF, ns_fd);
	if (ret < 0)
		pr_err("Can't install ns net reference\n");
	else
		pr_info("Saved netns fd for links restore\n");
	close(ns_fd);

	return ret >= 0 ? 0 : -1;
}

/*
 * If we want to modify iptables, we need to recevied the current
 * configuration, change it and load a new one into the kernel.
 * iptables can change or add only one rule.
 * iptables-restore allows to make a few changes for one iteration,
 * so it works faster.
 */
static int iptables_restore(bool ipv6, char *buf, int size)
{
	int pfd[2], ret = -1;
	char *cmd4[] = {"iptables-restore",  "--noflush", NULL};
	char *cmd6[] = {"ip6tables-restore", "--noflush", NULL};
	char **cmd = ipv6 ? cmd6 : cmd4;;

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

static int network_lock_internal()
{
	char conf[] =	"*filter\n"
				":CRIU - [0:0]\n"
				"-I INPUT -j CRIU\n"
				"-I OUTPUT -j CRIU\n"
				"-A CRIU -j DROP\n"
				"COMMIT\n";
	int ret = 0, nsret;

	if (switch_ns(root_item->pid.real, &net_ns_desc, &nsret))
		return -1;


	ret |= iptables_restore(false, conf, sizeof(conf) - 1);
	if (kdat.ipv6)
		ret |= iptables_restore(true, conf, sizeof(conf) - 1);

	if (restore_ns(nsret, &net_ns_desc))
		ret = -1;

	return ret;
}

static int network_unlock_internal()
{
	char conf[] =	"*filter\n"
			":CRIU - [0:0]\n"
			"-D INPUT -j CRIU\n"
			"-D OUTPUT -j CRIU\n"
			"-X CRIU\n"
			"COMMIT\n";
	int ret = 0, nsret;

	if (switch_ns(root_item->pid.real, &net_ns_desc, &nsret))
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
	char *aux;
	struct veth_pair *n;

	n = xmalloc(sizeof(*n));
	if (n == NULL)
		return -1;

	n->inside = in;
	n->outside = out;
	/*
	 * Does the out string specify a bridge for
	 * moving the outside end of the veth pair to?
	 */
	aux = strrchr(out, '@');
	if (aux) {
		*aux++ = '\0';
		n->bridge = aux;
	} else {
		n->bridge = NULL;
	}

	list_add(&n->node, &opts.veth_pairs);
	if (n->bridge)
		pr_debug("Added %s:%s@%s veth map\n", in, out, aux);
	else
		pr_debug("Added %s:%s veth map\n", in, out);
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

	ret = ns->net.seqsk = socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if (ret < 0) {
		pr_perror("Can't create seqsk for parasite");
		goto err_sq;
	}

	ret = 0;
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

static int collect_net_ns(struct ns_id *ns, void *oarg)
{
	bool for_dump = (oarg == (void *)1);
	int ret;

	pr_info("Collecting netns %d/%d\n", ns->id, ns->ns_pid);
	ret = prep_ns_sockets(ns, for_dump);
	if (ret)
		return ret;

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

int move_veth_to_bridge(void)
{
	int s;
	int ret;
	struct veth_pair *n;
	struct ifreq ifr;

	s = -1;
	ret = 0;
	list_for_each_entry(n, &opts.veth_pairs, node) {
		if (n->bridge == NULL)
			continue;

		pr_debug("\tMoving dev %s to bridge %s\n", n->outside, n->bridge);

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
		ifr.ifr_ifindex = if_nametoindex(n->outside);
		if (ifr.ifr_ifindex == 0) {
			pr_perror("Can't get index of %s", n->outside);
			ret = -1;
			break;
		}
		strlcpy(ifr.ifr_name, n->bridge, IFNAMSIZ);
		ret = ioctl(s, SIOCBRADDIF, &ifr);
		if (ret < 0) {
			pr_perror("Can't add interface %s to bridge %s",
				n->outside, n->bridge);
			break;
		}

		/*
		 * Make sure the device is up.  This is equivalent to:
		 * $ ip link set dev <device> up
		 */
		ifr.ifr_ifindex = 0;
		strlcpy(ifr.ifr_name, n->outside, IFNAMSIZ);
		ret = ioctl(s, SIOCGIFFLAGS, &ifr);
		if (ret < 0) {
			pr_perror("Can't get flags of interface %s", n->outside);
			break;
		}
		if (ifr.ifr_flags & IFF_UP)
			continue;
		ifr.ifr_flags |= IFF_UP;
		ret = ioctl(s, SIOCSIFFLAGS, &ifr);
		if (ret < 0) {
			pr_perror("Can't set flags of interface %s to 0x%x",
				n->outside, ifr.ifr_flags);
			break;
		}
	}

	if (s >= 0)
		close(s);
	return ret;
}
