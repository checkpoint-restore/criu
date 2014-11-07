#ifndef __CR_NS_H__
#define __CR_NS_H__

#include "files.h"

struct ns_desc {
	unsigned int	cflag;
	char		*str;
	size_t		len;
};

struct ns_id {
	unsigned int kid;
	unsigned int id;
	pid_t pid;
	struct ns_desc *nd;
	struct ns_id *next;

	/*
	 * For mount namespaces on restore -- indicates that
	 * the namespace in question is created (all mounts
	 * are mounted) and other tasks may do setns on it
	 * and proceed.
	 */
	futex_t ns_created;

	union {
		struct {
			struct mount_info *mntinfo_list;
			struct mount_info *mntinfo_tree;
		} mnt;

		struct {
			int nlsk;	/* for sockets collection */
			int seqsk;	/* to talk to parasite daemons */
		} net;
	};
};
extern struct ns_id *ns_ids;

#define NS_DESC_ENTRY(_cflag, _str)			\
	{						\
		.cflag		= _cflag,		\
		.str		= _str,			\
		.len		= sizeof(_str) - 1,	\
	}

extern bool check_ns_proc(struct fd_link *link);

extern struct ns_desc pid_ns_desc;
extern struct ns_desc user_ns_desc;
extern unsigned long root_ns_mask;

extern const struct fdtype_ops nsfile_dump_ops;
extern struct collect_image_info nsfile_cinfo;

extern int walk_namespaces(struct ns_desc *nd, int (*cb)(struct ns_id *, void *), void *oarg);
extern int collect_namespaces(bool for_dump);
extern int collect_mnt_namespaces(bool for_dump);
extern int dump_mnt_namespaces(void);
extern int dump_namespaces(struct pstree_item *item, unsigned int ns_flags);
extern int prepare_namespace(struct pstree_item *item, unsigned long clone_flags);
extern int try_show_namespaces(int pid);

extern int switch_ns(int pid, struct ns_desc *nd, int *rst);
extern int restore_ns(int rst, struct ns_desc *nd);

extern int dump_task_ns_ids(struct pstree_item *);
extern int predump_task_ns_ids(struct pstree_item *);
extern struct ns_id *rst_new_ns_id(unsigned int id, pid_t pid, struct ns_desc *nd);
extern int rst_add_ns_id(unsigned int id, pid_t pid, struct ns_desc *nd);
extern struct ns_id *lookup_ns_by_id(unsigned int id, struct ns_desc *nd);

extern int collect_user_namespaces(bool for_dump);
extern int prepare_userns(struct pstree_item *item);
extern int userns_uid(int uid);
extern int userns_gid(int gid);
extern int dump_user_ns(pid_t pid, int ns_id);
extern void free_userns_maps(void);

#endif /* __CR_NS_H__ */
