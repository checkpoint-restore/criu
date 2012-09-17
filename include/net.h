#ifndef __CR_NET_H__
#define __CR_NET_H__

#include "list.h"

struct cr_options;
void show_netdevices(int fd, struct cr_options *);

struct cr_fdset;
int dump_net_ns(int pid, struct cr_fdset *);
int prepare_net_ns(int pid);
int netns_pre_create(void);

struct veth_pair {
	struct list_head node;
	char *inside;
	char *outside;
};

extern int network_lock(void);
extern void network_unlock(void);
#endif
