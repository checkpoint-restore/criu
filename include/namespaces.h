#ifndef __CR_NS_H__
#define __CR_NS_H__

#include "files.h"

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

extern const struct fdtype_ops nsfile_dump_ops;
extern struct collect_image_info nsfile_cinfo;

extern int dump_namespaces(struct pstree_item *item, unsigned int ns_flags);
extern int prepare_namespace(struct pstree_item *item, unsigned long clone_flags);
extern int try_show_namespaces(int pid);

extern int switch_ns(int pid, struct ns_desc *nd, int *rst);
extern int restore_ns(int rst, struct ns_desc *nd);

extern int dump_task_ns_ids(struct pstree_item *);
extern int gen_predump_ns_mask(void);

#endif /* __CR_NS_H__ */
