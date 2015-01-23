#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <string.h>
#include <net/if_arp.h>
#include <sys/wait.h>
#include <sched.h>
#include <sys/mount.h>
#include <net/if.h>
#include <linux/sockios.h>

#include "imgset.h"
#include "syscall-types.h"
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
#include "protobuf.h"
#include "protobuf/netdev.pb-c.h"

static int ns_fd = -1;
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

	if (rlen >= 0)
		buf[rlen] = '\0';

	return rlen;
}

int write_netdev_img(NetDeviceEntry *nde, struct cr_imgset *fds)
{
	return pb_write_one(img_from_set(fds, CR_FD_NETDEV), nde, PB_NETDEV);
}

static int dump_one_netdev(int type, struct ifinfomsg *ifi,
		struct rtattr **tb, struct cr_imgset *fds,
		int (*dump)(NetDeviceEntry *, struct cr_imgset *))
{
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
		netdev.address.data = RTA_DATA(tb[IFLA_ADDRESS]);
		netdev.address.len = RTA_PAYLOAD(tb[IFLA_ADDRESS]);
		pr_info("Found ll addr (%02x:../%d) for %s\n",
				(int)netdev.address.data[0],
				(int)netdev.address.len, netdev.name);
	}

	if (!dump)
		dump = write_netdev_img;

	return dump(&netdev, fds);
}

static char *link_kind(struct ifinfomsg *ifi, struct rtattr **tb)
{
	struct rtattr *linkinfo[IFLA_INFO_MAX + 1];

	if (!tb[IFLA_LINKINFO]) {
		pr_err("No linkinfo for eth link %d\n", ifi->ifi_index);
		return NULL;
	}

	parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, tb[IFLA_LINKINFO]);
	if (!linkinfo[IFLA_INFO_KIND]) {
		pr_err("No kind for eth link %d\n", ifi->ifi_index);
		return NULL;
	}

	return RTA_DATA(linkinfo[IFLA_INFO_KIND]);
}

static int dump_unknown_device(struct ifinfomsg *ifi, char *kind,
		struct rtattr **tb, struct cr_imgset *fds)
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

static int dump_one_ethernet(struct ifinfomsg *ifi, char *kind,
		struct rtattr **tb, struct cr_imgset *fds)
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

	return dump_unknown_device(ifi, kind, tb, fds);
}

static int dump_one_gendev(struct ifinfomsg *ifi, char *kind,
		struct rtattr **tb, struct cr_imgset *fds)
{
	if (!strcmp(kind, "tun"))
		return dump_one_netdev(ND_TYPE__TUN, ifi, tb, fds, dump_tun_link);

	return dump_unknown_device(ifi, kind, tb, fds);
}

static int dump_one_voiddev(struct ifinfomsg *ifi, char *kind,
		struct rtattr **tb, struct cr_imgset *fds)
{
	if (!strcmp(kind, "venet"))
		/*
		 * If we meet a link we know about, such as
		 * OpenVZ's venet, save general parameters of
		 * it as external link.
		 */
		return dump_one_netdev(ND_TYPE__EXTLINK, ifi, tb, fds, NULL);

	return dump_unknown_device(ifi, kind, tb, fds);
}

static int dump_one_link(struct nlmsghdr *hdr, void *arg)
{
	struct cr_imgset *fds = arg;
	struct ifinfomsg *ifi;
	int ret = 0, len = hdr->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
	struct rtattr *tb[IFLA_MAX + 1];
	char *kind;

	ifi = NLMSG_DATA(hdr);

	if (len < 0) {
		pr_err("No iflas for link %d\n", ifi->ifi_index);
		return -1;
	}

	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);
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
	default:
unk:
		ret = dump_unknown_device(ifi, kind, tb, fds);
		break;
	}

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

static int restore_link(NetDeviceEntry *nde, int nlsk)
{
	pr_info("Restoring link %s type %d\n", nde->name, nde->type);

	switch (nde->type) {
	case ND_TYPE__LOOPBACK: /* fallthrough */
	case ND_TYPE__EXTLINK:  /* see comment in protobuf/netdev.proto */
		return restore_link_parms(nde, nlsk);
	case ND_TYPE__VETH:
		return restore_one_link(nde, nlsk, veth_link_info);
	case ND_TYPE__TUN:
		return restore_one_tun(nde, nlsk);
	default:
		pr_err("Unsupported link type %d\n", nde->type);
		break;
	}

	return -1;
}

static int restore_links(int pid)
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
		net_device_entry__free_unpacked(nde, NULL);
		if (ret)
			break;
	}

	close(nlsk);
	close_image(img);
	return ret;
}

static int run_ip_tool(char *arg1, char *arg2, int fdin, int fdout)
{
	char *ip_tool_cmd;
	int ret;

	pr_debug("\tRunning ip %s %s\n", arg1, arg2);

	ip_tool_cmd = getenv("CR_IP_TOOL");
	if (!ip_tool_cmd)
		ip_tool_cmd = "ip";

	ret = cr_system(fdin, fdout, -1, ip_tool_cmd,
				(char *[]) { "ip", arg1, arg2, NULL });
	if (ret) {
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
	ret = cr_system(fdin, fdout, -1, "sh", (char *[]) { "sh", "-c", cmd, NULL });
	if (ret)
		pr_err("%s failed\n", def_cmd);

	return ret;
}

static inline int dump_ifaddr(struct cr_imgset *fds)
{
	struct cr_img *img = img_from_set(fds, CR_FD_IFADDR);
	return run_ip_tool("addr", "save", -1, img_raw_fd(img));
}

static inline int dump_route(struct cr_imgset *fds)
{
	struct cr_img *img = img_from_set(fds, CR_FD_ROUTE);
	return run_ip_tool("route", "save", -1, img_raw_fd(img));
}

static inline int dump_iptables(struct cr_imgset *fds)
{
	struct cr_img *img = img_from_set(fds, CR_FD_IPTABLES);
	return run_iptables_tool("iptables-save", -1, img_raw_fd(img));
}

static int restore_ip_dump(int type, int pid, char *cmd)
{
	int ret = -1;
	struct cr_img *img;

	img = open_image(type, O_RSTR, pid);
	if (img) {
		ret = run_ip_tool(cmd, "restore", img_raw_fd(img), -1);
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
	return restore_ip_dump(CR_FD_ROUTE, pid, "route");
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
	if (!ret)
		ret = dump_links(fds);
	if (!ret)
		ret = dump_ifaddr(fds);
	if (!ret)
		ret = dump_route(fds);
	if (!ret)
		ret = dump_iptables(fds);

	close(ns_sysfs_fd);
	ns_sysfs_fd = -1;

	close_cr_imgset(&fds);
	return ret;
}

int prepare_net_ns(int pid)
{
	int ret;

	ret = restore_links(pid);
	if (!ret)
		ret = restore_ifaddr(pid);
	if (!ret)
		ret = restore_route(pid);
	if (!ret)
		ret = restore_iptables(pid);

	close(ns_fd);

	return ret;
}

int netns_pre_create(void)
{
	ns_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (ns_fd < 0) {
		pr_perror("Can't cache net fd");
		return -1;
	}

	pr_info("Saved netns fd for links restore\n");
	return 0;
}

int network_lock(void)
{
	pr_info("Lock network\n");

	/* Each connection will be locked on dump */
	if  (!(root_ns_mask & CLONE_NEWNET))
		return 0;

	return run_scripts(ACT_NET_LOCK);
}

void network_unlock(void)
{
	pr_info("Unlock network\n");

	cpt_unlock_tcp_connections();
	rst_unlock_tcp_connections();

	if (root_ns_mask & CLONE_NEWNET)
		run_scripts(ACT_NET_UNLOCK);
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

	if (ns->pid != getpid()) {
		pr_info("Switching to %d's net for collecting sockets\n", ns->pid);
		if (switch_ns(ns->pid, &net_ns_desc, &nsret))
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

	pr_info("Collecting netns %d/%d\n", ns->id, ns->pid);
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
		strncpy(ifr.ifr_name, n->bridge, IFNAMSIZ);
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
		strncpy(ifr.ifr_name, n->outside, IFNAMSIZ);
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
