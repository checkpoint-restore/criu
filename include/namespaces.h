#ifndef __CR_NS_H__
#define __CR_NS_H__

#include "crtools.h"
#include "pstree.h"
#include "files.h"

struct cr_options;

struct ns_desc {
	unsigned int	cflag;
	char		*str;
	size_t		len;
};

#define NS_DESC_ENTRY(_cflag, _str)			\
	{						\
		.cflag		= _cflag,		\
		.str		= _str,			\
		.len		= sizeof(_str) - 1,	\
	}

extern bool check_ns_proc(struct fd_link *link);

extern struct ns_desc pid_ns_desc;
extern struct ns_desc user_ns_desc;
extern unsigned long current_ns_mask;

extern int dump_ns_file(struct fd_parms *p, int lfd, const int fdinfo);
extern int collect_ns_files(void);

int dump_namespaces(struct pid *pid, unsigned int ns_flags);
int prepare_namespace(int pid, unsigned long clone_flags);
int try_show_namespaces(int pid, struct cr_options *o);

int switch_ns(int pid, struct ns_desc *nd, int *rst);
int restore_ns(int rst, struct ns_desc *nd);

int dump_task_ns_ids(struct pstree_item *);

#endif /* __CR_NS_H__ */
