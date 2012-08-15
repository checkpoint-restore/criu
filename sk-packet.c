#include <linux/if_packet.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <unistd.h>
#include <string.h>
#include "crtools.h"
#include "types.h"
#include "files.h"
#include "sockets.h"
#include "libnetlink.h"
#include "sk-packet.h"
#include "packet_diag.h"

#include "protobuf.h"
#include "protobuf/packet-sock.pb-c.h"
#include "protobuf/fdinfo.pb-c.h"

struct packet_sock_info {
	PacketSockEntry *pse;
	struct file_desc d;
};

struct packet_sock_desc {
	struct socket_desc sd;
	unsigned int type;
	unsigned short proto;
	struct packet_diag_info nli;
};

void show_packetsk(int fd, struct cr_options *o)
{
	pb_show_plain(fd, PB_PACKETSK);
}

static int dump_one_packet_fd(int lfd, u32 id, const struct fd_parms *p)
{
	PacketSockEntry psk = PACKET_SOCK_ENTRY__INIT;
	SkOptsEntry skopts = SK_OPTS_ENTRY__INIT;
	struct packet_sock_desc *sd;

	sd = (struct packet_sock_desc *)lookup_socket(p->stat.st_ino, PF_PACKET);
	if (sd < 0)
		return -1;

	pr_info("Dumping packet socket fd %d id %#x\n", lfd, id);
	BUG_ON(sd->sd.already_dumped);
	sd->sd.already_dumped = 1;

	psk.id = id;
	psk.type = sd->type;
	psk.flags = p->flags;
	psk.fown = (FownEntry *)&p->fown;
	psk.opts = &skopts;

	if (dump_socket_opts(lfd, &skopts))
		return -1;

	psk.protocol = sd->proto;
	psk.ifindex = sd->nli.pdi_index;
	psk.version = sd->nli.pdi_version;
	psk.reserve = sd->nli.pdi_reserve;
	psk.timestamp = sd->nli.pdi_tstamp;
	psk.copy_thresh = sd->nli.pdi_copy_thresh;
	psk.aux_data = (sd->nli.pdi_flags & PDI_AUXDATA ? true : false);
	psk.orig_dev = (sd->nli.pdi_flags & PDI_ORIGDEV ? true : false);
	psk.vnet_hdr = (sd->nli.pdi_flags & PDI_VNETHDR ? true : false);
	psk.loss = (sd->nli.pdi_flags & PDI_LOSS ? true : false);

	return pb_write_one(fdset_fd(glob_fdset, CR_FD_PACKETSK), &psk, PB_PACKETSK);
}

static const struct fdtype_ops packet_dump_ops = {
	.type		= FD_TYPES__PACKETSK,
	.dump		= dump_one_packet_fd,
};

int dump_one_packet_sk(struct fd_parms *p, int lfd, const struct cr_fdset *fds)
{
	return do_dump_gen_file(p, lfd, &packet_dump_ops, fds);
}

int packet_receive_one(struct nlmsghdr *hdr, void *arg)
{
	struct packet_diag_msg *m;
	struct rtattr *tb[PACKET_DIAG_MAX + 1];
	struct packet_sock_desc *sd;

	m = NLMSG_DATA(hdr);
	parse_rtattr(tb, PACKET_DIAG_MAX, (struct rtattr *)(m + 1),
			hdr->nlmsg_len - NLMSG_LENGTH(sizeof(*m)));
	pr_msg("Collect packet sock %u %u\n", m->pdiag_ino, (unsigned int)m->pdiag_num);

	if (!tb[PACKET_DIAG_INFO]) {
		pr_err("No packet sock info in nlm\n");
		return -1;
	}

	sd = xmalloc(sizeof(*sd));
	if (!sd)
		return -1;

	sd->type = m->pdiag_type;
	sd->proto = htons(m->pdiag_num);
	memcpy(&sd->nli, RTA_DATA(tb[PACKET_DIAG_INFO]), sizeof(sd->nli));

	return sk_collect_one(m->pdiag_ino, PF_PACKET, &sd->sd);
}

static int open_packet_sk(struct file_desc *d)
{
	struct packet_sock_info *psi;
	PacketSockEntry *pse;
	struct sockaddr_ll addr;
	int sk, yes;

	psi = container_of(d, struct packet_sock_info, d);
	pse = psi->pse;

	pr_info("Opening packet socket id %#x\n", pse->id);

	sk = socket(PF_PACKET, pse->type, pse->protocol);
	if (sk < 0) {
		pr_perror("Can't create packet sock");
		goto err;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = pse->ifindex;

	if (bind(sk, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		pr_perror("Can't bind packet socket");
		goto err_cl;
	}

	if (restore_opt(sk, SOL_PACKET, PACKET_VERSION, &pse->version))
		goto err_cl;

	if (restore_opt(sk, SOL_PACKET, PACKET_RESERVE, &pse->reserve))
		goto err_cl;

	if (restore_opt(sk, SOL_PACKET, PACKET_TIMESTAMP, &pse->timestamp))
		goto err_cl;

	if (restore_opt(sk, SOL_PACKET, PACKET_COPY_THRESH, &pse->copy_thresh))
		goto err_cl;

	if (pse->aux_data) {
		yes = 1;
		if (restore_opt(sk, SOL_PACKET, PACKET_AUXDATA, &yes))
			goto err_cl;
	}

	if (pse->orig_dev) {
		yes = 1;
		if (restore_opt(sk, SOL_PACKET, PACKET_ORIGDEV, &yes))
			goto err_cl;
	}

	if (pse->vnet_hdr) {
		yes = 1;
		if (restore_opt(sk, SOL_PACKET, PACKET_VNET_HDR, &yes))
			goto err_cl;
	}

	if (pse->loss) {
		yes = 1;
		if (restore_opt(sk, SOL_PACKET, PACKET_LOSS, &yes))
			goto err_cl;
	}

	if (rst_file_params(sk, pse->fown, pse->flags))
		goto err_cl;

	if (restore_socket_opts(sk, pse->opts))
		goto err_cl;

	return sk;

err_cl:
	close(sk);
err:
	return -1;
}

static struct file_desc_ops packet_sock_desc_ops = {
	.type = FD_TYPES__PACKETSK,
	.open = open_packet_sk,
};

static int collect_one_packet_sk(void *o, ProtobufCMessage *base)
{
	struct packet_sock_info *si = o;

	si->pse = pb_msg(base, PacketSockEntry);
	file_desc_add(&si->d, si->pse->id, &packet_sock_desc_ops);

	return 0;
}

int collect_packet_sockets(void)
{
	return collect_image(CR_FD_PACKETSK, PB_PACKETSK,
			sizeof(struct packet_sock_info), collect_one_packet_sk);
}
