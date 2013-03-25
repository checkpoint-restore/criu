#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "crtools.h"
#include "files.h"
#include "sockets.h"
#include "util.h"

#include "protobuf.h"
#include "protobuf/sk-netlink.pb-c.h"
#include "netlink_diag.h"
#include "libnetlink.h"

struct netlink_sk_desc {
	struct socket_desc	sd;
	u32                     portid;
	u32			*groups;
	u32			gsize;
	u32                     dst_portid;
	u32			dst_group;
	u8			state;
	u8			protocol;
};

int netlink_receive_one(struct nlmsghdr *hdr, void *arg)
{
	struct rtattr *tb[NETLINK_DIAG_MAX+1];
	struct netlink_diag_msg *m;
	struct netlink_sk_desc *sd;
	unsigned long *groups;

	m = NLMSG_DATA(hdr);
	pr_info("Collect netlink sock 0x%x\n", m->ndiag_ino);

	sd = xmalloc(sizeof(*sd));
	if (!sd)
		return -1;

	sd->protocol = m->ndiag_protocol;
	sd->portid = m->ndiag_portid;
	sd->dst_portid = m->ndiag_dst_portid;
	sd->dst_group = m->ndiag_dst_group;
	sd->state = m->ndiag_state;

	parse_rtattr(tb, NETLINK_DIAG_MAX, (struct rtattr *)(m + 1),
		     hdr->nlmsg_len - NLMSG_LENGTH(sizeof(*m)));

	if (tb[NETLINK_DIAG_GROUPS]) {
		sd->gsize = RTA_PAYLOAD(tb[NETLINK_DIAG_GROUPS]);
		groups = RTA_DATA(tb[NETLINK_DIAG_GROUPS]);

		sd->groups = xmalloc(sizeof(sd->gsize));
		if (!sd->groups) {
			xfree(sd);
			return -1;
		}
		memcpy(sd->groups, groups, sd->gsize);
	} else {
		sd->groups = NULL;
		sd->gsize = 0;
	}

	return sk_collect_one(m->ndiag_ino, PF_NETLINK, &sd->sd);
}

void show_netlinksk(int fd, struct cr_options *o)
{
	pb_show_plain(fd, PB_NETLINKSK);
}
