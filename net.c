#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <string.h>
#include <net/if_arp.h>
#include <sys/wait.h>
#include "syscall-types.h"
#include "namespaces.h"
#include "net.h"
#include "libnetlink.h"

#include "protobuf.h"
#include "protobuf/netdev.pb-c.h"

void show_netdevices(int fd, struct cr_options *opt)
{
	pb_show_plain(fd, PB_NETDEV);
}

static int dump_one_netdev(int type, struct ifinfomsg *ifi,
		struct rtattr **tb, struct cr_fdset *fds)
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

	return pb_write_one(fdset_fd(fds, CR_FD_NETDEV), &netdev, PB_NETDEV);
}

static int dump_one_ethernet(struct ifinfomsg *ifi,
		struct rtattr **tb, struct cr_fdset *fds)
{
	struct rtattr *linkinfo[IFLA_INFO_MAX + 1];
	char *kind;

	if (!tb[IFLA_LINKINFO]) {
		pr_err("No linkinfo for eth link %d\n", ifi->ifi_index);
		return -1;
	}

	parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, tb[IFLA_LINKINFO]);
	if (!linkinfo[IFLA_INFO_KIND]) {
		pr_err("No kind for eth link %d\n", ifi->ifi_index);
		return -1;
	}

	kind = RTA_DATA(linkinfo[IFLA_INFO_KIND]);
	if (!strcmp(kind, "veth"))
		/*
		 * This is not correct. The peer of the veth device may
		 * be either outside or inside the netns we're working
		 * on, but there's currently no way of finding this out.
		 *
		 * Sigh... we have to assume, that the veth device is a
		 * connection to the outer world and just dump this end :(
		 */
		return dump_one_netdev(ND_TYPE__VETH, ifi, tb, fds);

	pr_err("Unknown eth kind %s link %d\n", kind, ifi->ifi_index);
	return -1;
}

static int dump_one_link(struct nlmsghdr *hdr, void *arg)
{
	struct cr_fdset *fds = arg;
	struct ifinfomsg *ifi;
	int ret = 0, len = hdr->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
	struct rtattr * tb[IFLA_MAX+1];

	ifi = NLMSG_DATA(hdr);

	if (len < 0) {
		pr_err("No iflas for link %d\n", ifi->ifi_index);
		return -1;
	}

	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);

	pr_info("\tLD: Got link %d, type %d\n", ifi->ifi_index, ifi->ifi_type);

	switch (ifi->ifi_type) {
	case ARPHRD_LOOPBACK:
		ret = dump_one_netdev(ND_TYPE__LOOPBACK, ifi, tb, fds);
		break;
	case ARPHRD_ETHER:
		ret = dump_one_ethernet(ifi, tb, fds);
		break;
	default:
		pr_err("Unsupported link type %d\n", ifi->ifi_type);
		ret = 0; /* just skip for now */
		break;
	}

	return ret;
}

static int dump_links(struct cr_fdset *fds)
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

	ret = do_rtnl_req(sk, &req, sizeof(req), dump_one_link, fds);
	close(sk);
out:
	return ret;
}

static int restore_link_cb(struct nlmsghdr *hdr, void *arg)
{
	pr_info("Got responce on SETLINK =)\n");
	return 0;
}

static int restore_one_link(NetDeviceEntry *nde, int nlsk)
{
	struct {
		struct nlmsghdr h;
		struct ifinfomsg i;
	} req;

	memset(&req, 0, sizeof(req));

	req.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.h.nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE;
	req.h.nlmsg_type = RTM_NEWLINK;
	req.h.nlmsg_seq = CR_NLMSG_SEQ;
	req.i.ifi_family = AF_PACKET;
	req.i.ifi_index = nde->ifindex;
	req.i.ifi_flags = nde->flags;

	/* FIXME -- restore mtu as well */

	pr_info("Restoring netdev idx %d\n", nde->ifindex);
	return do_rtnl_req(nlsk, &req, sizeof(req), restore_link_cb, NULL);
}

static int restore_link(NetDeviceEntry *nde, int nlsk)
{
	pr_info("Restoring link type %d\n", nde->type);

	switch (nde->type) {
	case ND_TYPE__LOOPBACK:
		return restore_one_link(nde, nlsk);
	case ND_TYPE__VETH:
		break;
	}

	BUG_ON(1);
	return -1;
}

static int restore_links(int pid)
{
	int fd, nlsk, ret;
	NetDeviceEntry *nde;

	fd = open_image_ro(CR_FD_NETDEV, pid);
	if (fd < 0)
		return -1;

	nlsk = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nlsk < 0) {
		pr_perror("Can't create nlk socket");
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
	int pid, ret, status;

	pr_debug("\tRunning ip %s %s\n", arg1, arg2);

	pid = fork();
	if (pid < 0) {
		pr_perror("Can't forn IP tool");
		return -1;
	}

	if (!pid) {
		char *ip_tool_cmd;

		ip_tool_cmd = getenv("CR_IP_TOOL");
		if (!ip_tool_cmd)
			ip_tool_cmd = "ip";

		if (fdin < 0)
			close(0);
		else if (fdin != 0) {
			dup2(fdin, 0);
			close(fdin);
		}

		if (fdout < 0)
			close(1);
		else if (fdout != 1) {
			dup2(fdout, 1);
			close(fdout);
		}

		if (log_get_fd() != 2) {
			dup2(log_get_fd(), 2);
			close(log_get_fd());
		}

		execlp(ip_tool_cmd, "ip", arg1, arg2, NULL);
		exit(-1);
	}

	ret = waitpid(pid, &status, 0);
	if (ret < 0) {
		pr_perror("Can't wait IP tool");
		return -1;
	}

	if (!(WIFEXITED(status) && !WEXITSTATUS(status))) {
		pr_err("IP tool failed on %s %s with %d (%d)\n", arg1, arg2,
				status, WEXITSTATUS(status));
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

	ret = fd = open_image_ro(type, pid);
	if (fd > 0) {
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

int dump_net_ns(int pid, struct cr_fdset *fds)
{
	int ret;

	ret = switch_ns(pid, CLONE_NEWNET, "net", NULL);
	if (!ret)
		ret = dump_links(fds);
	if (!ret)
		ret = dump_ifaddr(fds);
	if (!ret)
		ret = dump_route(fds);

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

	return ret;
}
