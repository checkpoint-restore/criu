#ifndef __CR_NET_H__
#define __CR_NET_H__

#include "list.h"

struct cr_imgset;
extern int dump_net_ns(int ns_id);
extern int prepare_net_ns(int pid);
extern int netns_pre_create(void);

struct veth_pair {
	struct list_head node;
	char *inside;
	char *outside;
	char *bridge;
};

extern int collect_net_namespaces(bool for_dump);

extern int network_lock(void);
extern void network_unlock(void);

extern struct ns_desc net_ns_desc;

#include "protobuf/netdev.pb-c.h"
extern int write_netdev_img(NetDeviceEntry *nde, struct cr_imgset *fds);
extern int read_ns_sys_file(char *path, char *buf, int len);
extern int restore_link_parms(NetDeviceEntry *nde, int nlsk);

extern int veth_pair_add(char *in, char *out);
extern int move_veth_to_bridge(void);

#endif /* __CR_NET_H__ */
