#ifndef __CR_SK_PACKET_H__
#define __CR_SK_PACKET_H__

#ifndef PACKET_TIMESTAMP
#define PACKET_TIMESTAMP	17
#endif

struct cr_fdset;
struct fd_parms;
struct cr_options;
struct vma_area;

int dump_one_packet_sk(struct fd_parms *p, int lfd, const struct cr_fdset *fds);
int collect_packet_sockets(void);
void show_packetsk(int fd, struct cr_options *);

int dump_socket_map(struct vma_area *vma);
int get_socket_fd(int pid, VmaEntry *vma);

extern int packet_receive_one(struct nlmsghdr *h, void *arg);

#ifndef PACKET_VNET_HDR
#define PACKET_VNET_HDR 15
#endif

#ifndef PACKET_FANOUT
#define PACKET_FANOUT	18

struct tpacket_req3 {
	unsigned int tp_block_size;
	unsigned int tp_block_nr;
	unsigned int tp_frame_size;
	unsigned int tp_frame_nr;
	unsigned int tp_retire_blk_tov;
	unsigned int tp_sizeof_priv;
	unsigned int tp_feature_req_word;
};
#endif

#endif
