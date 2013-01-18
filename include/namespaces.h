#ifndef __CR_NS_H__
#define __CR_NS_H__

#include "crtools.h"
#include "pstree.h"

int dump_namespaces(struct pid *pid, unsigned int ns_flags);
int prepare_namespace(int pid, unsigned long clone_flags);
struct cr_options;
int try_show_namespaces(int pid, struct cr_options *);

struct ns_desc {
	unsigned int cflag;
	char *str;
};

int switch_ns(int pid, struct ns_desc *nd, int *rst);
int restore_ns(int rst, struct ns_desc *nd);
extern struct ns_desc pid_ns_desc;

struct pstree_item;
int dump_task_ns_ids(struct pstree_item *);

extern unsigned long current_ns_mask;

#endif /* __CR_NS_H__ */
