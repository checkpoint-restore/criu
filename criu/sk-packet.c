#include <linux/if_packet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <libnl3/netlink/msg.h>
#include <unistd.h>
#include <string.h>
#include "imgset.h"
#include "files.h"
#include "sockets.h"
#include "libnetlink.h"
#include "sk-packet.h"
#include "packet_diag.h"
#include "vma.h"
#include <arpa/inet.h>

#include "protobuf.h"
#include "xmalloc.h"
#include "images/packet-sock.pb-c.h"
#include "images/fdinfo.pb-c.h"
#include "namespaces.h"

#undef  LOG_PREFIX
#define LOG_PREFIX "packet: "

struct packet_sock_info {
	PacketSockEntry *pse;
	struct file_desc d;
};

struct packet_mreq_max {
	int		mr_ifindex;
	unsigned short	mr_type;
	unsigned short	mr_alen;
	unsigned char	mr_address[MAX_ADDR_LEN];
};

struct packet_sock_desc {
	struct socket_desc sd;
	unsigned int file_id;
	unsigned int type;
	unsigned short proto;
	struct packet_diag_info nli;
	int mreq_n;
	struct packet_diag_mclist *mreqs;
	unsigned int fanout;
	struct packet_diag_ring *rx, *tx;
};

#define NO_FANOUT	((unsigned int)-1)

static int dump_mreqs(PacketSockEntry *psk, struct packet_sock_desc *sd)
{
	int i;

	if (!sd->mreq_n)
		return 0;

	pr_debug("\tdumping %d mreqs\n", sd->mreq_n);
	psk->mclist = xmalloc(sd->mreq_n * sizeof(psk->mclist[0]));
	if (!psk->mclist)
		return -1;

	for (i = 0; i < sd->mreq_n; i++) {
		struct packet_diag_mclist *m = &sd->mreqs[i];
		PacketMclist *im;

		if (m->pdmc_count != 1) {
			pr_err("Multiple MC membership not supported (but can be)\n");
			goto err;
		}

		pr_debug("\tmr%d: idx %d type %d\n", i,
				m->pdmc_index, m->pdmc_type);

		im = xmalloc(sizeof(*im));
		if (!im)
			goto err;

		packet_mclist__init(im);
		psk->mclist[i] = im;
		psk->n_mclist++;

		im->index = m->pdmc_index;
		im->type = m->pdmc_type;

		switch (m->pdmc_type) {
			case PACKET_MR_MULTICAST:
			case PACKET_MR_UNICAST:
				im->addr.len = m->pdmc_alen;
				im->addr.data = xmalloc(m->pdmc_alen);
				if (!im->addr.data)
					goto err;

				memcpy(im->addr.data, m->pdmc_addr, m->pdmc_alen);
				break;
			case PACKET_MR_PROMISC:
			case PACKET_MR_ALLMULTI:
				break;
			default:
				pr_err("Unknown mc membership type %d\n", m->pdmc_type);
				goto err;
		}
	}

	return 0;
err:
	return -1;
}

static PacketRing *dump_ring(struct packet_diag_ring *dr)
{
	PacketRing *ring;

	ring = xmalloc(sizeof(*ring));
	if (!ring)
		return NULL;

	packet_ring__init(ring);

	ring->block_size = dr->pdr_block_size;
	ring->block_nr = dr->pdr_block_nr;
	ring->frame_size = dr->pdr_frame_size;
	ring->frame_nr = dr->pdr_frame_nr;
	ring->retire_tmo = dr->pdr_retire_tmo;
	ring->sizeof_priv = dr->pdr_sizeof_priv;
	ring->features = dr->pdr_features;

	return ring;
}

static int dump_rings(PacketSockEntry *psk, struct packet_sock_desc *sd)
{
	if (sd->rx) {
		psk->rx_ring = dump_ring(sd->rx);
		if (!psk->rx_ring)
			return -1;
	}

	if (sd->tx) {
		psk->tx_ring = dump_ring(sd->tx);
		if (!psk->tx_ring)
			return -1;
	}

	return 0;
}

static int dump_one_packet_fd(int lfd, u32 id, const struct fd_parms *p)
{
	FileEntry fe = FILE_ENTRY__INIT;
	PacketSockEntry psk = PACKET_SOCK_ENTRY__INIT;
	SkOptsEntry skopts = SK_OPTS_ENTRY__INIT;
	struct packet_sock_desc *sd;
	int i, ret;

	sd = (struct packet_sock_desc *)lookup_socket(p->stat.st_ino, PF_PACKET, 0);
	if (IS_ERR_OR_NULL(sd)) {
		pr_err("Can't find packet socket %"PRIu64"\n", p->stat.st_ino);
		return -1;
	}

	pr_info("Dumping packet socket fd %d id %#x\n", lfd, id);
	BUG_ON(sd->sd.already_dumped);
	sd->sd.already_dumped = 1;

	psk.id = sd->file_id = id;
	psk.ns_id = sd->sd.sk_ns->id;
	psk.has_ns_id = true;
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

	ret = dump_mreqs(&psk, sd);
	if (ret)
		goto out;

	if (sd->fanout != NO_FANOUT) {
		psk.has_fanout = true;
		psk.fanout = sd->fanout;
	}

	ret = dump_rings(&psk, sd);
	if (ret)
		goto out;

	fe.type = FD_TYPES__PACKETSK;
	fe.id = psk.id;
	fe.psk = &psk;

	ret = pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE);
out:
	release_skopts(&skopts);
	xfree(psk.rx_ring);
	xfree(psk.tx_ring);
	for (i = 0; i < psk.n_mclist; i++)
		xfree(psk.mclist[i]->addr.data);
	xfree(psk.mclist);
	return ret;
}

const struct fdtype_ops packet_dump_ops = {
	.type		= FD_TYPES__PACKETSK,
	.dump		= dump_one_packet_fd,
};

int dump_socket_map(struct vma_area *vma)
{
	struct packet_sock_desc *sd;

	sd = (struct packet_sock_desc *)lookup_socket(vma->vm_socket_id, PF_PACKET, 0);
	if (IS_ERR_OR_NULL(sd)) {
		pr_err("Can't find packet socket %u to mmap\n", vma->vm_socket_id);
		return -1;
	}

	if (!sd->file_id) {
		pr_err("Mmap-ed socket %u not open\n", vma->vm_socket_id);
		return -1;
	}

	pr_info("Dumping socket map %x -> %"PRIx64"\n", sd->file_id, vma->e->start);
	vma->e->shmid = sd->file_id;
	return 0;
}

static int packet_save_mreqs(struct packet_sock_desc *sd, struct nlattr *mc)
{
	sd->mreq_n = nla_len(mc) / sizeof(struct packet_diag_mclist);
	pr_debug("\tGot %d mreqs\n", sd->mreq_n);
	sd->mreqs = xmalloc(nla_len(mc));
	if (!sd->mreqs)
		return -1;

	memcpy(sd->mreqs, nla_data(mc), nla_len(mc));
	return 0;
}

int packet_receive_one(struct nlmsghdr *hdr, struct ns_id *ns, void *arg)
{
	struct packet_diag_msg *m;
	struct nlattr *tb[PACKET_DIAG_MAX + 1];
	struct packet_sock_desc *sd;

	m = NLMSG_DATA(hdr);
	nlmsg_parse(hdr, sizeof(struct packet_diag_msg),
			tb, PACKET_DIAG_MAX, NULL);
	pr_info("Collect packet sock %u %u\n", m->pdiag_ino, (unsigned int)m->pdiag_num);

	if (!tb[PACKET_DIAG_INFO]) {
		pr_err("No packet sock info in nlm\n");
		return -1;
	}

	if (!tb[PACKET_DIAG_MCLIST]) {
		pr_err("No packet sock mclist in nlm\n");
		return -1;
	}

	sd = xmalloc(sizeof(*sd));
	if (!sd)
		return -1;

	sd->file_id = 0;
	sd->type = m->pdiag_type;
	sd->proto = htons(m->pdiag_num);
	sd->rx = NULL;
	sd->tx = NULL;
	memcpy(&sd->nli, nla_data(tb[PACKET_DIAG_INFO]), sizeof(sd->nli));

	if (packet_save_mreqs(sd, tb[PACKET_DIAG_MCLIST]))
		goto err;

	if (tb[PACKET_DIAG_FANOUT])
		sd->fanout = *(__u32 *)RTA_DATA(tb[PACKET_DIAG_FANOUT]);
	else
		sd->fanout = NO_FANOUT;

	if (tb[PACKET_DIAG_RX_RING]) {
		sd->rx = xmalloc(sizeof(*sd->rx));
		if (sd->rx == NULL)
			goto err;
		memcpy(sd->rx, RTA_DATA(tb[PACKET_DIAG_RX_RING]), sizeof(*sd->rx));
	}

	if (tb[PACKET_DIAG_TX_RING]) {
		sd->tx = xmalloc(sizeof(*sd->tx));
		if (sd->tx == NULL)
			goto err;
		memcpy(sd->tx, RTA_DATA(tb[PACKET_DIAG_TX_RING]), sizeof(*sd->tx));
	}

	return sk_collect_one(m->pdiag_ino, PF_PACKET, &sd->sd, ns);
err:
	xfree(sd->tx);
	xfree(sd->rx);
	xfree(sd);
	return -1;
}

static int open_socket_map(int pid, struct vma_area *vm)
{
	VmaEntry *vma = vm->e;
	struct file_desc *fd;
	struct fdinfo_list_entry *le;

	pr_info("Getting packet socket fd for %d:%x\n",
			pid, (int)vma->shmid);
	fd = find_file_desc_raw(FD_TYPES__PACKETSK, vma->shmid);
	if (!fd) {
		pr_err("No packet socket %x\n", (int)vma->shmid);
		return -1;
	}

	list_for_each_entry(le, &fd->fd_info_head, desc_list)
		if (le->pid == pid) {
			int fd;

			/*
			 * Restorer will close the mmap-ed fd
			 */

			fd = dup(le->fe->fd);
			if (fd < 0) {
				pr_perror("Can't dup packet sk");
				return -1;
			}

			vma->fd = fd;
			return 0;
		}

	pr_err("No open packet socket %x by %d\n", (int)vma->shmid, pid);
	return -1;
}

int collect_socket_map(struct vma_area *vma)
{
	vma->vm_open = open_socket_map;
	return 0;
}

static int restore_mreqs(int sk, PacketSockEntry *pse)
{
	int i;

	for (i = 0; i < pse->n_mclist; i++) {
		PacketMclist *ml;
		struct packet_mreq_max mreq;

		ml = pse->mclist[i];
		pr_info("Restoring mreq type %d\n", ml->type);

		if (ml->addr.len > sizeof(mreq.mr_address)) {
			pr_err("To big mcaddr %zu\n", ml->addr.len);
			return -1;
		}

		mreq.mr_ifindex = ml->index;
		mreq.mr_type = ml->type;
		mreq.mr_alen = ml->addr.len;
		memcpy(mreq.mr_address, ml->addr.data, ml->addr.len);

		if (restore_opt(sk, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq))
			return -1;
	}

	return 0;
}

static int restore_ring(int sk, int type, PacketRing *ring)
{
	struct tpacket_req3 req;

	if (!ring)
		return 0;

	pr_debug("\tRestoring %d ring\n", type);

	req.tp_block_size = ring->block_size;
	req.tp_block_nr = ring->block_nr;
	req.tp_frame_size = ring->frame_size;
	req.tp_frame_nr = ring->frame_nr;
	req.tp_retire_blk_tov = ring->retire_tmo;
	req.tp_sizeof_priv = ring->sizeof_priv;
	req.tp_feature_req_word = ring->features;

	return restore_opt(sk, SOL_PACKET, type, &req);
}

static int restore_rings(int sk, PacketSockEntry *psk)
{
	if (restore_ring(sk, PACKET_RX_RING, psk->rx_ring))
		return -1;

	if (restore_ring(sk, PACKET_TX_RING, psk->tx_ring))
		return -1;

	return 0;
}

static int open_packet_sk_spkt(PacketSockEntry *pse, int *new_fd)
{
	struct sockaddr addr_spkt;
	int sk;

	sk = socket(PF_PACKET, pse->type, pse->protocol);
	if (sk < 0) {
		pr_perror("Can't create packet socket");
		return -1;
	}

	memset(&addr_spkt, 0, sizeof(addr_spkt));
	addr_spkt.sa_family = AF_PACKET;

	// if the socket was bound to any device
	if (pse->ifindex > 0) {
		const size_t sa_data_size = sizeof(addr_spkt.sa_data);
		struct ifreq req;

		memset(&req, 0, sizeof(req));
		req.ifr_ifindex = pse->ifindex;

		if (ioctl(sk, SIOCGIFNAME, &req) < 0) {
			pr_perror("Can't get interface name (ifindex %d)", pse->ifindex);
			goto err;
		}

		memcpy(addr_spkt.sa_data, req.ifr_name, sa_data_size);
		addr_spkt.sa_data[sa_data_size - 1] = 0;

		if (bind(sk, &addr_spkt, sizeof(addr_spkt)) < 0) {
			pr_perror("Can't bind packet socket to %s", req.ifr_name);
			goto err;
		}
	}

	if (rst_file_params(sk, pse->fown, pse->flags))
		goto err;

	if (restore_socket_opts(sk, pse->opts))
		goto err;

	*new_fd = sk;
	return 0;

err:
	close(sk);
	return -1;
}

static int open_packet_sk(struct file_desc *d, int *new_fd)
{
	struct packet_sock_info *psi;
	PacketSockEntry *pse;
	struct sockaddr_ll addr;
	int sk, yes;

	psi = container_of(d, struct packet_sock_info, d);
	pse = psi->pse;

	pr_info("Opening packet socket id %#x\n", pse->id);

	if (set_netns(pse->ns_id))
		return -1;

	if (pse->type == SOCK_PACKET)
		return open_packet_sk_spkt(pse, new_fd);

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

	if (restore_mreqs(sk, pse))
		goto err_cl;

	if (restore_rings(sk, pse))
		goto err_cl;

	if (pse->has_fanout) {
		pr_info("Restoring fanout %x\n", pse->fanout);
		if (restore_opt(sk, SOL_PACKET, PACKET_FANOUT, &pse->fanout))
			goto err_cl;
	}

	if (rst_file_params(sk, pse->fown, pse->flags))
		goto err_cl;

	if (restore_socket_opts(sk, pse->opts))
		goto err_cl;

	*new_fd = sk;
	return 0;

err_cl:
	close(sk);
err:
	return -1;
}

static struct file_desc_ops packet_sock_desc_ops = {
	.type = FD_TYPES__PACKETSK,
	.open = open_packet_sk,
};

static int collect_one_packet_sk(void *o, ProtobufCMessage *base, struct cr_img *i)
{
	struct packet_sock_info *si = o;

	si->pse = pb_msg(base, PacketSockEntry);
	return file_desc_add(&si->d, si->pse->id, &packet_sock_desc_ops);
}

struct collect_image_info packet_sk_cinfo = {
	.fd_type = CR_FD_PACKETSK,
	.pb_type = PB_PACKET_SOCK,
	.priv_size = sizeof(struct packet_sock_info),
	.collect = collect_one_packet_sk,
};
