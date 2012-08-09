#include <linux/if_packet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include "crtools.h"
#include "types.h"
#include "files.h"
#include "sockets.h"
#include "sk-packet.h"

#include "protobuf.h"
#include "protobuf/packet-sock.pb-c.h"
#include "protobuf/fdinfo.pb-c.h"

struct packet_sock_info {
	PacketSockEntry *pse;
	struct file_desc d;
};

void show_packetsk(int fd, struct cr_options *o)
{
	pb_show_plain(fd, PB_PACKETSK);
}

static int dump_one_packet_fd(int lfd, u32 id, const struct fd_parms *p)
{
	int type;
	PacketSockEntry psk = PACKET_SOCK_ENTRY__INIT;
	SkOptsEntry skopts = SK_OPTS_ENTRY__INIT;
	struct sockaddr_ll addr;
	socklen_t alen;

	pr_info("Dumping packet socket fd %d id %#x\n", lfd, id);

	if (dump_opt(lfd, SOL_SOCKET, SO_TYPE, &type))
		return -1;

	psk.id = id;
	psk.type = type;
	psk.flags = p->flags;
	psk.fown = (FownEntry *)&p->fown;
	psk.opts = &skopts;

	if (dump_socket_opts(lfd, &skopts))
		return -1;

	alen = sizeof(addr);
	if (getsockname(lfd, (struct sockaddr *)&addr, &alen) < 0) {
		pr_perror("Can't get packet sock name");
		return -1;
	}

	psk.protocol = addr.sll_protocol;
	psk.ifindex = addr.sll_ifindex;

	if (dump_opt(lfd, SOL_PACKET, PACKET_VERSION, &psk.version))
		return -1;

	return pb_write_one(fdset_fd(glob_fdset, CR_FD_PACKETSK), &psk, PB_PACKETSK);
}

static const struct fdtype_ops packet_dump_ops = {
	.type		= FD_TYPES__PACKETSK,
	.make_gen_id	= make_gen_id,
	.dump		= dump_one_packet_fd,
};

int dump_one_packet_sk(struct fd_parms *p, int lfd, const struct cr_fdset *fds)
{
	return do_dump_gen_file(p, lfd, &packet_dump_ops, fds);
}

static int open_packet_sk(struct file_desc *d)
{
	struct packet_sock_info *psi;
	PacketSockEntry *pse;
	struct sockaddr_ll addr;
	int sk;

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
