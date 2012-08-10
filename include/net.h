#ifndef __CR_NET_H__
#define __CR_NET_H__
struct cr_options;
void show_netdevices(int fd, struct cr_options *);

struct cr_fdset;
int dump_net_ns(int pid, struct cr_fdset *);
int prepare_net_ns(int pid);
int netns_pre_create(void);
#endif
