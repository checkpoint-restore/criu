#ifndef __CR_SK_PACKET_H__
#define __CR_SK_PACKET_H__

#ifndef PACKET_TIMESTAMP
#define PACKET_TIMESTAMP	17
#endif

struct cr_imgset;
struct fd_parms;
struct vma_area;

extern struct collect_image_info packet_sk_cinfo;

extern int dump_socket_map(struct vma_area *vma);
extern int collect_socket_map(struct vma_area *);

struct nlmsghdr;
extern int packet_receive_one(struct nlmsghdr *h, struct ns_id *ns, void *arg);

#ifndef PACKET_VNET_HDR
#define PACKET_VNET_HDR 15
#endif

#ifndef PACKET_FANOUT
#define PACKET_FANOUT	18
#endif

#ifndef TPACKET3_HDRLEN
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

#endif /* __CR_SK_PACKET_H__ */
