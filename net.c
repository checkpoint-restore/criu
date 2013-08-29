#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <string.h>
#include <net/if_arp.h>
#include <sys/wait.h>
#include <sched.h>
#include <sys/mount.h>

#include "syscall-types.h"
#include "namespaces.h"
#include "net.h"
#include "libnetlink.h"
#include "crtools.h"
#include "sk-inet.h"
#include "tun.h"
#include "util-pie.h"

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

int write_netdev_img(NetDeviceEntry *nde, struct cr_fdset *fds)
{
	return pb_write_one(fdset_fd(fds, CR_FD_NETDEV), nde, PB_NETDEV);
}

static int dump_one_netdev(int type, struct ifinfomsg *ifi,
		struct rtattr **tb, struct cr_fdset *fds,
		int (*dump)(NetDeviceEntry *, struct cr_fdset *))
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

static int dump_one_ethernet(struct ifinfomsg *ifi,
		struct rtattr **tb, struct cr_fdset *fds)
{
	char *kind;

	kind = link_kind(ifi, tb);
	if (!kind)
		goto unk;

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
unk:
	pr_err("Unknown eth kind %s link %d\n", kind, ifi->ifi_index);
	return -1;
}

static int dump_one_gendev(struct ifinfomsg *ifi,
		struct rtattr **tb, struct cr_fdset *fds)
{
	char *kind;

	kind = link_kind(ifi, tb);
	if (!kind)
		goto unk;

	if (!strcmp(kind, "tun"))
		return dump_one_netdev(ND_TYPE__TUN, ifi, tb, fds, dump_tun_link);

unk:
	pr_err("Unknown ARPHRD_NONE kind %s link %d\n", kind, ifi->ifi_index);
	return -1;
}

static int dump_one_link(struct nlmsghdr *hdr, void *arg)
{
	struct cr_fdset *fds = arg;
	struct ifinfomsg *ifi;
	int ret = 0, len = hdr->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
	struct rtattr *tb[IFLA_MAX + 1];

	ifi = NLMSG_DATA(hdr);

	if (len < 0) {
		pr_err("No iflas for link %d\n", ifi->ifi_index);
		return -1;
	}

	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);

	pr_info("\tLD: Got link %d, type %d\n", ifi->ifi_index, ifi->ifi_type);

	switch (ifi->ifi_type) {
	case ARPHRD_LOOPBACK:
		ret = dump_one_netdev(ND_TYPE__LOOPBACK, ifi, tb, fds, NULL);
		break;
	case ARPHRD_ETHER:
		ret = dump_one_ethernet(ifi, tb, fds);
		break;
	case ARPHRD_NONE:
		ret = dump_one_gendev(ifi, tb, fds);
		break;
	default:
		pr_err("Unsupported link type %d, kind %s\n",
				ifi->ifi_type, link_kind(ifi, tb));
		ret = 0; /* just skip for now */
		break;
	}

	return ret;
}

static int do_dump_links(int (*cb)(struct nlmsghdr *h, void *), void *arg)
{
	int sk, ret;
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;

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

	ret = do_rtnl_req(sk, &req, sizeof(req), cb, arg);
	close(sk);
out:
	return ret;
}

static int dump_links(struct cr_fdset *fds)
{
	pr_info("Dumping netns links\n");

	return do_dump_links(dump_one_link, fds);
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

	return do_rtnl_req(nlsk, &req, req.h.nlmsg_len, restore_link_cb, NULL);
}

int restore_link_parms(NetDeviceEntry *nde, int nlsk)
{
	return do_rtm_link_req(RTM_SETLINK, nde, nlsk, NULL);
}

static int restore_one_link(NetDeviceEntry *nde, int nlsk,
		int (*link_info)(NetDeviceEntry *, struct newlink_req *))
{
	pr_info("Restoring netdev idx %d\n", nde->ifindex);
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
	pr_info("Restoring link type %d\n", nde->type);

	switch (nde->type) {
	case ND_TYPE__LOOPBACK:
		return restore_one_link(nde, nlsk, NULL);
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
	int fd, nlsk, ret;
	NetDeviceEntry *nde;

	fd = open_image(CR_FD_NETDEV, O_RSTR, pid);
	if (fd < 0)
		return -1;

	nlsk = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nlsk < 0) {
		pr_perror("Can't create nlk socket");
		close_safe(&fd);
		return -1;
	}

	while (1) {
		ret = pb_read_one_eof(fd, &nde, PB_NETDEV);
		if (ret <= 0)
			break;

		ret = restore_link(nde, nlsk);
		net_device_entry__free_unpacked(nde, NULL);
		if (ret)
			break;
	}

	close(nlsk);
	close(fd);
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

static inline int dump_ifaddr(struct cr_fdset *fds)
{
	return run_ip_tool("addr", "save", -1, fdset_fd(fds, CR_FD_IFADDR));
}

static inline int dump_route(struct cr_fdset *fds)
{
	return run_ip_tool("route", "save", -1, fdset_fd(fds, CR_FD_ROUTE));
}

static int restore_ip_dump(int type, int pid, char *cmd)
{
	int fd, ret;

	ret = fd = open_image(type, O_RSTR, pid);
	if (fd >= 0) {
		ret = run_ip_tool(cmd, "restore", fd, -1);
		close(fd);
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

int dump_net_ns(int pid, struct cr_fdset *fds)
{
	int ret;

	ret = switch_ns(pid, &net_ns_desc, NULL);
	if (!ret)
		ret = mount_ns_sysfs();
	if (!ret)
		ret = dump_links(fds);
	if (!ret)
		ret = dump_ifaddr(fds);
	if (!ret)
		ret = dump_route(fds);

	close(ns_sysfs_fd);
	ns_sysfs_fd = -1;

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

	close(ns_fd);

	return ret;
}

int netns_pre_create(void)
{
	ns_fd = open("/proc/self/ns/net", O_RDONLY);
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
	if  (!(current_ns_mask & CLONE_NEWNET))
		return 0;

	return run_scripts("network-lock");
}

void network_unlock(void)
{
	pr_info("Unlock network\n");

	if  (!(current_ns_mask & CLONE_NEWNET)) {
		cpt_unlock_tcp_connections();
		rst_unlock_tcp_connections();

		return;
	}

	run_scripts("network-unlock");
}

struct ns_desc net_ns_desc = NS_DESC_ENTRY(CLONE_NEWNET, "net");
