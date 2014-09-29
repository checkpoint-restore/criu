#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "imgset.h"
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

		sd->groups = xmalloc(sd->gsize);
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

static bool can_dump_netlink_sk(int lfd)
{
	int ret;

	ret = fd_has_data(lfd);
	if (ret == 1)
		pr_err("The socket has data to read\n");

	return ret == 0;
}

static int dump_one_netlink_fd(int lfd, u32 id, const struct fd_parms *p)
{
	struct netlink_sk_desc *sk;
	NetlinkSkEntry ne = NETLINK_SK_ENTRY__INIT;
	SkOptsEntry skopts = SK_OPTS_ENTRY__INIT;

	sk = (struct netlink_sk_desc *)lookup_socket(p->stat.st_ino, PF_NETLINK, 0);
	if (IS_ERR(sk))
		goto err;

	ne.id = id;
	ne.ino = p->stat.st_ino;

	if (!can_dump_netlink_sk(lfd))
		goto err;

	if (sk) {
		BUG_ON(sk->sd.already_dumped);

		ne.protocol = sk->protocol;
		ne.portid = sk->portid;
		ne.groups = sk->groups;


		ne.n_groups = sk->gsize / sizeof(ne.groups[0]);
		/*
		 * On 64-bit sk->gsize is multiple to 8 bytes (sizeof(long)),
		 * so remove the last 4 bytes if they are empty.
		 */
		if (ne.n_groups && sk->groups[ne.n_groups - 1] == 0)
			ne.n_groups -= 1;

		if (ne.n_groups > 1) {
			pr_err("%d %x\n", sk->gsize, sk->groups[1]);
			pr_err("The netlink socket 0x%x has more than 32 groups\n", ne.ino);
			return -1;
		}
		if (sk->groups && !sk->portid) {
			pr_err("The netlink socket 0x%x is bound to groups but not to portid\n", ne.ino);
			return -1;
		}
		ne.state = sk->state;
		ne.dst_portid = sk->dst_portid;
		ne.dst_group = sk->dst_group;
	} else { /* unconnected and unbound socket */
		int val;
		socklen_t aux = sizeof(val);

		if (getsockopt(lfd, SOL_SOCKET, SO_PROTOCOL, &val, &aux) < 0) {
			pr_perror("Unable to get protocol for netlink socket");
			goto err;
		}

		ne.protocol = val;
	}

	ne.fown = (FownEntry *)&p->fown;
	ne.opts	= &skopts;

	if (dump_socket_opts(lfd, &skopts))
		goto err;

	if (pb_write_one(img_from_set(glob_imgset, CR_FD_NETLINK_SK), &ne, PB_NETLINK_SK))
		goto err;

	return 0;
err:
	return -1;
}

const struct fdtype_ops netlink_dump_ops = {
	.type		= FD_TYPES__NETLINKSK,
	.dump		= dump_one_netlink_fd,
};

struct netlink_sock_info {
	NetlinkSkEntry *nse;
	struct file_desc d;
};

static int open_netlink_sk(struct file_desc *d)
{
	struct netlink_sock_info *nsi;
	NetlinkSkEntry *nse;
	struct sockaddr_nl addr;
	int sk = -1;

	nsi = container_of(d, struct netlink_sock_info, d);
	nse = nsi->nse;

	pr_info("Opening netlink socket id %#x\n", nse->id);

	sk = socket(PF_NETLINK, SOCK_RAW, nse->protocol);
	if (sk < 0) {
		pr_perror("Can't create netlink sock");
		goto err;
	}

	if (nse->portid) {
		memset(&addr, 0, sizeof(addr));
		addr.nl_family = AF_NETLINK;
		if (nse->n_groups > 1) {
			pr_err("Groups above 32 are not supported yet\n");
			goto err;
		}
		if (nse->n_groups)
			addr.nl_groups = nse->groups[0];
		addr.nl_pid = nse->portid;

		if (bind(sk, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			pr_perror("Can't bind netlink socket");
			goto err;
		}
	}

	if (nse->state == NETLINK_CONNECTED) {
		addr.nl_family = AF_NETLINK;
		addr.nl_groups = 1 << (nse->dst_group - 1);
		addr.nl_pid = nse->dst_portid;
		if (connect(sk, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			pr_perror("Can't connect netlink socket");
			goto err;
		}
	}

	if (rst_file_params(sk, nse->fown, nse->flags))
		goto err;

	if (restore_socket_opts(sk, nse->opts))
		goto err;

	return sk;
err:
	close(sk);
	return -1;
}

static struct file_desc_ops netlink_sock_desc_ops = {
	.type = FD_TYPES__NETLINKSK,
	.open = open_netlink_sk,
};

static int collect_one_netlink_sk(void *o, ProtobufCMessage *base)
{
	struct netlink_sock_info *si = o;

	si->nse = pb_msg(base, NetlinkSkEntry);
	return file_desc_add(&si->d, si->nse->id, &netlink_sock_desc_ops);
}

struct collect_image_info netlink_sk_cinfo = {
	.fd_type = CR_FD_NETLINK_SK,
	.pb_type = PB_NETLINK_SK,
	.priv_size = sizeof(struct netlink_sock_info),
	.collect = collect_one_netlink_sk,
	.flags = COLLECT_OPTIONAL,
};
