#ifndef __CR_NS_H__
#define __CR_NS_H__

#include "compiler.h"
#include "files.h"

/* including syscall-types.h gives another weird error; do we really need to
 * define this twice? */
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP	0x02000000
#endif

/* Nested namespaces are supported only for these types */
#define CLONE_SUBNS	(CLONE_NEWNS)

struct ns_desc {
	unsigned int	cflag;
	char		*str;
	size_t		len;
};

enum ns_type {
	NS_UNKNOWN = 0,
	NS_CRIU,
	NS_ROOT,
	NS_OTHER,
};

struct ns_id {
	unsigned int kid;
	unsigned int id;
	pid_t ns_pid;
	struct ns_desc *nd;
	struct ns_id *next;
	enum ns_type type;

	/*
	 * For mount namespaces on restore -- indicates that
	 * the namespace in question is created (all mounts
	 * are mounted) and other tasks may do setns on it
	 * and proceed.
	 */
	futex_t ns_populated;

	union {
		struct {
			struct mount_info *mntinfo_list;
			struct mount_info *mntinfo_tree;
			int ns_fd;
			int root_fd;
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
extern int prepare_namespace_before_tasks(void);
extern int prepare_namespace(struct pstree_item *item, unsigned long clone_flags);

extern int switch_ns(int pid, struct ns_desc *nd, int *rst);
extern int restore_ns(int rst, struct ns_desc *nd);

extern int dump_task_ns_ids(struct pstree_item *);
extern int predump_task_ns_ids(struct pstree_item *);
extern struct ns_id *rst_new_ns_id(unsigned int id, pid_t pid, struct ns_desc *nd, enum ns_type t);
extern int rst_add_ns_id(unsigned int id, struct pstree_item *, struct ns_desc *nd);
extern struct ns_id *lookup_ns_by_id(unsigned int id, struct ns_desc *nd);

extern int collect_user_namespaces(bool for_dump);
extern int prepare_userns(struct pstree_item *item);
extern int stop_usernsd(void);

extern uid_t userns_uid(uid_t uid);
extern gid_t userns_gid(gid_t gid);

extern int dump_user_ns(pid_t pid, int ns_id);
extern void free_userns_maps(void);

typedef int (*uns_call_t)(void *arg, int fd, pid_t pid);
/*
 * Async call -- The call is guaranteed to be done till the
 * CR_STATE_COMPLETE happens. The function may return even
 * before the call starts.
 * W/o flag the call is synchronous -- this function returns
 * strictly after the call finishes.
 */
#define UNS_ASYNC	0x1
/*
 * The call returns an FD which should be sent back. Conflicts
 * with UNS_ASYNC.
 */
#define UNS_FDOUT	0x2

#define MAX_UNSFD_MSG_SIZE 4096

/*
 * When we're restoring inside user namespace, some things are
 * not allowed to be done there due to insufficient capabilities.
 * If the operation in question can be offloaded to another process,
 * this call allows to do that.
 *
 * In case we're not in userns, just call the callback immediatelly
 * in the context of calling task.
 */
extern int __userns_call(const char *func_name, uns_call_t call, int flags,
			 void *arg, size_t arg_size, int fd);

#define userns_call(__call, __flags, __arg, __arg_size, __fd)	\
	__userns_call(__stringify(__call), __call, __flags,	\
		      __arg, __arg_size, __fd)

#endif /* __CR_NS_H__ */
