#ifndef __CR_NET_H__
#define __CR_NET_H__

#include <linux/netlink.h>

#include "common/list.h"
#include "external.h"

#ifndef RTM_GETNSID
#define RTM_GETNSID		90
#endif

struct cr_imgset;
struct ns_id;
extern int dump_net_ns(struct ns_id *ns);
extern int prepare_net_namespaces(void);
extern void fini_net_namespaces(void);
extern int netns_keep_nsfd(void);

struct pstree_item;
extern int restore_task_net_ns(struct pstree_item *current);

struct veth_pair {
	struct list_head node;
	char *inside;
	char *outside;
	char *bridge;
};

extern int collect_net_namespaces(bool for_dump);

extern int network_lock(void);
extern void network_unlock(void);
extern int network_lock_internal(void);

extern struct ns_desc net_ns_desc;

#include "images/netdev.pb-c.h"
extern int write_netdev_img(NetDeviceEntry *nde, struct cr_imgset *fds, struct nlattr **info);
extern int read_ns_sys_file(char *path, char *buf, int len);
struct net_link;
extern int restore_link_parms(struct net_link *link, int nlsk);

extern int veth_pair_add(char *in, char *out);
extern int macvlan_ext_add(struct external *ext);
extern int move_veth_to_bridge(void);

extern int kerndat_link_nsid(void);
extern int net_get_nsid(int rtsk, int fd, int *nsid);
extern struct ns_id *net_get_root_ns(void);
extern int kerndat_nsid(void);
extern void check_has_netns_ioc(int fd, bool *kdat_val, const char *name);
extern int net_set_ext(struct ns_id *ns);
extern struct ns_id *get_root_netns(void);
extern int read_net_ns_img(void);

#endif /* __CR_NET_H__ */
