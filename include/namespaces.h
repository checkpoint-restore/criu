#ifndef __CR_NS_H__
#define __CR_NS_H__

#include "crtools.h"
#include "pstree.h"

struct cr_options;

struct ns_desc {
	unsigned int	cflag;
	char		*str;
};

extern struct ns_desc pid_ns_desc;
extern unsigned long current_ns_mask;

int dump_namespaces(struct pid *pid, unsigned int ns_flags);
int prepare_namespace(int pid, unsigned long clone_flags);
int try_show_namespaces(int pid, struct cr_options *o);

int switch_ns(int pid, struct ns_desc *nd, int *rst);
int restore_ns(int rst, struct ns_desc *nd);

int dump_task_ns_ids(struct pstree_item *);

#endif /* __CR_NS_H__ */
