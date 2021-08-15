#include <netinet/udp.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/sockios.h>

#include "../soccr/soccr.h"
#include "xmalloc.h"
#include "sk-inet.h"
#include "netfilter.h"
#include "namespaces.h"

#include "protobuf.h"
#include "images/udp-queue.pb-c.h"

struct udp_packet {
	UdpPacketEntry *upe;
	char *data;
	struct list_head packet_list;
};

static int dump_udp_sockaddr(UdpPacketEntry *upe, union libsoccr_addr *sa_addr, int family)
{
	void *ip_addr;

	if (family == AF_INET) {
		upe->port = ntohs(sa_addr->v4.sin_port);
		ip_addr = (void *)&sa_addr->v4.sin_addr;
	} else {
		upe->port = ntohs(sa_addr->v6.sin6_port);
		ip_addr = (void *)&sa_addr->v6.sin6_addr;
		upe->flow_info = sa_addr->v6.sin6_flowinfo;
		upe->scope_id = sa_addr->v6.sin6_scope_id;
	}
	memcpy(upe->addr, ip_addr, pb_repeated_size(upe, addr));
	return 0;
}

/* Return length of the received packet, -1 if error */
static int recv_one_udp(int fd, union libsoccr_addr *sa_addr, int addr_len, char *data, int max_len, char *cmsg,
			int cmsg_len)
{
	int ret;
	struct iovec iov;
	struct msghdr msg;

	iov.iov_base = data;
	iov.iov_len = max_len;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsg;
	msg.msg_controllen = cmsg_len;
	msg.msg_name = &sa_addr->sa;
	msg.msg_namelen = addr_len;

	ret = recvmsg(fd, &msg, MSG_DONTWAIT | MSG_PEEK);
	if (ret < 0) {
		if (errno == EAGAIN)
			return 0;
		pr_perror("recvmsg fail: error");
		return -1;
	}

	return ret;
}

static void free_udp_packet(struct udp_packet *up)
{
	xfree(up->upe->addr);
	xfree(up->upe);
	xfree(up);
}

static int dump_recv_queue(int fd, int family, unsigned int *inq_pkt, struct list_head *packets, char **rcvq_data)
{
	UdpPacketEntry *upe;
	char *data, *r_data = NULL;
	int ret, pkt_len, addr_len, aux;
	struct udp_packet *up, *n;
	union libsoccr_addr sa_addr;
	int num_of_pkts = 0;
	socklen_t tmp;

	/* The default value of SO_PEEK_OFF is -1 and the socket does not change
	 * the SO_PEEK_OFF after peeking the front packet. Later recv will return
	 * the same front packet. Set it 0 so it will increase SO_PEEK_OFF after
	 * peeking.
	 */
	aux = 0;
	if (setsockopt(fd, SOL_SOCKET, SO_PEEK_OFF, &aux, sizeof(aux))) {
		/* CentOS 7 does not support SO_PEEK_OFF on AF_INET sockets, the
		 * peek off is 0 every recvmsg
		 */
		if (errno != EOPNOTSUPP) {
			pr_perror("Can't get SO_PEEK_OFF");
			return -1;
		}
	}

	addr_len = family == AF_INET ? sizeof(sa_addr.v4) : sizeof(sa_addr.v6);
	/* Get the max DRAM size */
	tmp = sizeof(pkt_len);
	if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &pkt_len, &tmp)) {
		pr_perror("Can't get SO_RCVBUF");
		return -1;
	}

	r_data = xmalloc(pkt_len);
	if (!r_data)
		return -1;

	data = r_data;

	while (1) {
		ret = -1;
		upe = xmalloc(sizeof(UdpPacketEntry));
		if (!upe)
			goto free_data;

		udp_packet_entry__init(upe);

		ret = recv_one_udp(fd, &sa_addr, addr_len, data, pkt_len, NULL, 0);
		if (ret < 0)
			goto free_upe;
		else if (ret == 0) {
			/* We receive all the packets */
			xfree(upe);
			break;
		}

		aux = ret;
		upe->pkt_len = ret;

		ret = -1;
		upe->n_addr = family == AF_INET ? PB_ALEN_INET : PB_ALEN_INET6;
		upe->addr = xmalloc(pb_repeated_size(upe, addr));
		if (!upe->addr)
			goto free_upe;
		dump_udp_sockaddr(upe, &sa_addr, family);

		up = xmalloc(sizeof(struct udp_packet));
		if (!up)
			goto free_addr;

		up->upe = upe;
		up->data = data;
		list_add_tail(&up->packet_list, packets);
		num_of_pkts += 1;
		data += aux;
		pkt_len -= aux;
	}

	ret = 0;
	goto out;

free_addr:
	xfree(upe->addr);
free_upe:
	xfree(upe);
free_data:
	list_for_each_entry_safe(up, n, packets, packet_list)
		free_udp_packet(up);
	xfree(r_data);
	r_data = NULL;
out:
	*rcvq_data = r_data;
	*inq_pkt = num_of_pkts;
	return ret;
}

static int dump_send_queue(int fd, int family, unsigned int *outq_pkt, struct udp_packet **packet)
{
	int aux = 1, ret = -1, outq_max, addr_len;
	char *data;
	UdpPacketEntry *upe;
	union libsoccr_addr sa_addr;
	struct udp_packet *pkt;

	*outq_pkt = 0;
	upe = xmalloc(sizeof(UdpPacketEntry));
	if (!upe)
		return -1;
	udp_packet_entry__init(upe);

	if (setsockopt(fd, SOL_UDP, UDP_REPAIR, &aux, sizeof(aux))) {
		pr_info("Can't turn on UDP repair, skip dumping UDP send queue\n");
		ret = 0;
		goto free_upe;
	}

	aux = 0;
	if (setsockopt(fd, SOL_SOCKET, SO_PEEK_OFF, &aux, sizeof(aux))) {
		/* CentOS 7 does not support SO_PEEK_OFF on AF_INET sockets, the
		 * peek off is 0 every recvmsg
		 */
		if (errno != EOPNOTSUPP) {
			pr_perror("Can't set SO_PEEK_OFF");
			goto free_upe;
		}
	}

	if (ioctl(fd, SIOCOUTQ, &outq_max)) {
		pr_perror("Can't read SIOCOUTQ");
		goto free_upe;
	}

	data = xmalloc(outq_max);
	if (!data)
		goto free_upe;

	addr_len = family == AF_INET ? sizeof(sa_addr.v4) : sizeof(sa_addr.v6);
	ret = recv_one_udp(fd, &sa_addr, addr_len, data, outq_max, NULL, 0);
	if (ret <= 0)
		goto free_data;

	*outq_pkt = 1;
	upe->pkt_len = ret;
	upe->n_addr = family == AF_INET ? PB_ALEN_INET : PB_ALEN_INET6;

	ret = -1;
	upe->addr = xmalloc(pb_repeated_size(upe, addr));
	if (!upe->addr)
		goto free_data;
	dump_udp_sockaddr(upe, &sa_addr, family);

	pkt = xmalloc(sizeof(struct udp_packet));
	if (!pkt)
		goto free_addr;

	pkt->upe = upe;
	pkt->data = data;
	*packet = pkt;
	return 0;

free_addr:
	xfree(upe->addr);
free_data:
	xfree(data);
free_upe:
	xfree(upe);
	*outq_pkt = 0;
	return ret;
}

int write_img_queue(struct cr_img *img, struct udp_packet *up)
{
	if (pb_write_one(img, up->upe, PB_UDP_PACKET))
		return -1;
	if (write_img_buf(img, up->data, up->upe->pkt_len))
		return -1;
	return 0;
}

int dump_one_udp(int fd, struct inet_sk_desc *sk, int family)
{
	int aux, ret, peek_off, err = -1;
	struct cr_img *img;
	UdpQueueEntry udp_queue_entry = UDP_QUEUE_ENTRY__INIT;
	struct udp_packet *up, *n;
	socklen_t len;
	LIST_HEAD(rcvq_packets);
	/* The send queue only contains 1 packet */
	struct udp_packet *sndq_packet = NULL;
	char *rcvq_data = NULL;

	pr_info("Dumping a UDP socket %d\n", sk->sd.ino);

	if (dump_opt(fd, SOL_UDP, UDP_CORK, &aux))
		return -1;

	udp_queue_entry.cork = false;
	if (aux)
		udp_queue_entry.cork = true;

	img = open_image(CR_FD_UDP_QUEUE, O_DUMP, sk->sd.ino);
	if (!img)
		return -1;

	len = sizeof(peek_off);
	if (getsockopt(fd, SOL_SOCKET, SO_PEEK_OFF, &peek_off, &len)) {
		/* CentOS 7 does not support SO_PEEK_OFF on AF_INET sockets, the
		 * peek off is 0 every recvmsg
		 */
		if (errno == EOPNOTSUPP) {
			pr_warn("SO_PEEK_OFF is not supported on UDP socket\n");
		} else {
			pr_perror("Can't read SO_PEEK_OFF");
			goto out;
		}
	}

	ret = dump_recv_queue(fd, family, &udp_queue_entry.inq_pkt, &rcvq_packets, &rcvq_data);
	if (ret < 0) {
		pr_err("Dump recv queue failed\n");
		goto restore_off;
	}

	ret = dump_send_queue(fd, family, &udp_queue_entry.outq_pkt, &sndq_packet);
	if (ret < 0) {
		pr_err("Dump send queue failed\n");
		goto free_inq;
	}

	ret = pb_write_one(img, &udp_queue_entry, PB_UDP_QUEUE);
	if (ret < 0)
		goto free_outq;

	list_for_each_entry(up, &rcvq_packets, packet_list) {
		if (write_img_queue(img, up))
			goto free_outq;
	}

	if (sndq_packet) {
		if (write_img_queue(img, sndq_packet))
			goto free_outq;
	}

	err = 0;

free_outq:
	if (sndq_packet)
		free_udp_packet(sndq_packet);
free_inq:
	list_for_each_entry_safe(up, n, &rcvq_packets, packet_list)
		free_udp_packet(up);
	xfree(rcvq_data);
restore_off:
	setsockopt(fd, SOL_SOCKET, SO_PEEK_OFF, &peek_off, sizeof(peek_off));
out:
	close_image(img);
	return err;
}

static int send_one_udp(int fd, union libsoccr_addr *sa_dst, int addr_len, char *data, int len, char *cmsg,
			int cmsg_len)
{
	struct iovec iov;
	struct msghdr msg;
	int ret;

	iov.iov_base = data;
	iov.iov_len = len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsg;
	msg.msg_controllen = cmsg_len;
	msg.msg_name = &sa_dst->sa;
	msg.msg_namelen = addr_len;

	ret = sendmsg(fd, &msg, 0);
	if (ret < 0) {
		pr_perror("sendmsg failed");
		return -1;
	} else if (ret != len) {
		pr_warn("sendmsg drops some bytes\n");
	}

	return 0;
}

static void *create_pktinfo_cmsg(UdpPacketEntry *upe, int family, int *cmsg_len)
{
	struct cmsghdr *cmsg;
	union libsoccr_addr sa_src;
	int len;

	if (family == AF_INET) {
		memcpy(&sa_src.v4.sin_addr.s_addr, upe->addr, sizeof(sa_src.v4.sin_addr.s_addr));

		len = CMSG_SPACE(sizeof(struct in_pktinfo));
		cmsg = xzalloc(len);
		if (!cmsg)
			return NULL;

		cmsg->cmsg_level = SOL_IP;
		cmsg->cmsg_type = IP_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
		((struct in_pktinfo *)CMSG_DATA(cmsg))->ipi_spec_dst = sa_src.v4.sin_addr;
	} else {
		memcpy(&sa_src.v6.sin6_addr.s6_addr, upe->addr, sizeof(sa_src.v6.sin6_addr.s6_addr));

		len = CMSG_SPACE(sizeof(struct in6_pktinfo));
		cmsg = xzalloc(len);
		if (!cmsg)
			return NULL;

		cmsg->cmsg_level = SOL_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
		((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr = sa_src.v6.sin6_addr;
		/* FIXME: Do we need to set the scope_id? */
	}

	*cmsg_len = len;
	return cmsg;
}

static int _restore_recv_queue(struct inet_sk_info *ii, UdpPacketEntry *upe, char *data, int len)
{
	int local_sk, addr_len, cmsg_len, val = 1, err = -1;
	union libsoccr_addr local_sk_addr = {};
	union libsoccr_addr sa_dst;
	char *cmsg;
	int family = ii->ie->family;
	int ifindex = 0;
	int mark = SOCCR_MARK;

	if (family == AF_INET) {
		inet_pton(AF_INET, "127.0.0.255", &local_sk_addr.v4.sin_addr);
		local_sk_addr.v4.sin_port = htons(upe->port);
		local_sk_addr.v4.sin_family = AF_INET;
		addr_len = sizeof(local_sk_addr.v4);
	} else {
		inet_pton(AF_INET6, "::255", &local_sk_addr.v6.sin6_addr);
		local_sk_addr.v6.sin6_port = htons(upe->port);
		local_sk_addr.v6.sin6_family = AF_INET6;
		addr_len = sizeof(local_sk_addr.v6);
	}

	local_sk = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if (local_sk < 0) {
		pr_perror("Can't create a temporary UDP socket");
		return -1;
	}

	if (setsockopt(local_sk, SOL_IP, IP_TRANSPARENT, &val, sizeof(val))) {
		pr_perror("Can't set IP_TRANSPARENT");
		goto close_sk;
	}

	/* Use IP_FREEBIND to bind to a fake address to avoid port collision.
	 * Port collision can still occur when another application bind to that
	 * port in all interfaces.
	 */
	if (setsockopt(local_sk, SOL_IP, IP_FREEBIND, &val, sizeof(val))) {
		pr_perror("Can't set IP_FREEBIND");
		goto close_sk;
	}

	/* Bind this to the same port as the dumped packets */
	if (bind(local_sk, &local_sk_addr.sa, addr_len)) {
		/* If we can't do this then just drop with a warning */
		pr_warn("Can't restore source port of UDP packets, drop packet: %s\n", strerror(errno));
		err = 0;
		goto close_sk;
	}

	if (setsockopt(local_sk, SOL_SOCKET, SO_MARK, &mark, sizeof(mark))) {
		pr_perror("Can't set SO_MARK");
		goto close_sk;
	}

	cmsg = create_pktinfo_cmsg(upe, family, &cmsg_len);
	if (!cmsg)
		goto close_sk;

	if (ii->ie->ifname) {
		ifindex = if_nametoindex(ii->ie->ifname);
		if (!ifindex) {
			pr_err("couldn't find ifindex for %s\n", ii->ie->ifname);
			goto free_cmsg;
		}
	}

	/* Do we need to restore flow_info? */
	addr_len = restore_sockaddr(&sa_dst, family, ii->ie->src_port, ii->ie->src_addr, ifindex);

	if (send_one_udp(local_sk, &sa_dst, addr_len, data, len, cmsg, cmsg_len))
		goto free_cmsg;

	err = 0;

free_cmsg:
	xfree(cmsg);
close_sk:
	close(local_sk);
	return err;
}

static int restore_recv_queue(struct inet_sk_info *ii, int num_packets, struct cr_img *img)
{
	int i, ret = -1;
	UdpPacketEntry *upe = NULL;
	char *data = NULL;

	for (i = 0; i < num_packets; i++) {
		if (pb_read_one(img, &upe, PB_UDP_PACKET) < 0)
			goto out;
		data = xrealloc(data, upe->pkt_len);
		if (!data)
			goto out;

		if (read_img_buf(img, data, upe->pkt_len) < 0)
			goto free_data;

		if (_restore_recv_queue(ii, upe, data, upe->pkt_len))
			pr_warn("Failed to restore a UDP packet in recv queue\n");
	}

	ret = 0;

free_data:
	xfree(data);
out:
	if (upe)
		udp_packet_entry__free_unpacked(upe, NULL);
	return ret;
}

static int restore_send_queue(int fd, int outq_pkt, struct cr_img *img, int family)
{
	UdpPacketEntry *upe;
	char *data;
	union libsoccr_addr sa_dst;
	int addr_len, packet_len, ret = -1;

	/* Empty send queue */
	if (!outq_pkt)
		return 0;

	if (pb_read_one(img, &upe, PB_UDP_PACKET) < 0)
		goto out;

	packet_len = upe->pkt_len;
	data = xmalloc(packet_len);
	if (!data)
		goto free_data;

	pr_info("Restore send queue: %d\n", packet_len);
	if (read_img_buf(img, data, packet_len) < 0)
		goto free_data;

	/* FIXME: What about flow_info */
	addr_len = restore_sockaddr(&sa_dst, family, upe->port, upe->addr, upe->scope_id);

	if (send_one_udp(fd, &sa_dst, addr_len, data, packet_len, NULL, 0)) {
		pr_err("Restore send queue failed\n");
		goto free_data;
	}

	ret = 0;

free_data:
	xfree(data);
out:
	udp_packet_entry__free_unpacked(upe, NULL);
	return ret;
}

int restore_one_udp(int fd, struct inet_sk_info *ii)
{
	UdpQueueEntry *udp_queue_entry;
	struct cr_img *img;
	int aux, ret = -1;

	pr_info("Restoring UDP socket id %x ino %x\n", ii->ie->id, ii->ie->ino);

	img = open_image(CR_FD_UDP_QUEUE, O_RSTR, ii->ie->ino);
	if (!img)
		return -1;

	if (pb_read_one(img, &udp_queue_entry, PB_UDP_QUEUE) < 0)
		goto err;

	if (udp_queue_entry->cork) {
		aux = 1;
		if (restore_opt(fd, SOL_UDP, UDP_CORK, &aux))
			goto err;
	}

	if (restore_prepare_socket(fd))
		goto err;

	if (restore_recv_queue(ii, udp_queue_entry->inq_pkt, img))
		goto err;

	if (restore_send_queue(fd, udp_queue_entry->outq_pkt, img, ii->ie->family))
		goto err;

	ret = 0;

err:
	udp_queue_entry__free_unpacked(udp_queue_entry, NULL);
	close_image(img);
	return ret;
}
