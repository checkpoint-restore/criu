#ifndef __CR_NS_H__
#define __CR_NS_H__

#include <sys/ioctl.h>

#include "common/compiler.h"
#include "files.h"
#include "common/list.h"
#include "images/ns.pb-c.h"

#ifndef CLONE_NEWNS
#define CLONE_NEWNS	0x00020000
#endif

#ifndef CLONE_NEWPID
#define CLONE_NEWPID	0x20000000
#endif

#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS	0x04000000
#endif

#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC	0x08000000
#endif

#ifndef CLONE_NEWNET
#define CLONE_NEWNET	0x40000000
#endif

#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER	0x10000000
#endif

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP	0x02000000
#endif

#define CLONE_ALLNS	(CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWCGROUP)

/* Nested namespaces are supported only for these types */
#define CLONE_SUBNS	(CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWUSER)

#define EXTRA_SIZE	20

#ifndef NSIO
#define NSIO    0xb7
#define NS_GET_USERNS   _IO(NSIO, 0x1)
#define NS_GET_PARENT   _IO(NSIO, 0x2)
#endif

#define NS_INVALID_XID (~0U)

struct ns_desc {
	unsigned int	cflag;
	char		*str;
	size_t		len;
};

struct user_ns_extra {
	char	*uid;
	char	*gid;
};

/* struct join_ns is used for storing parameters specified by --join-ns */
struct join_ns {
	struct list_head	list;
	char			*ns_file;
	struct ns_desc		*nd;	/* namespace descriptor */
	int			ns_fd;
	/* extra options of --join-ns, like uid&gid in user namespace */
	union {
		struct user_ns_extra	user_extra;
		char			*common_extra;
	} extra_opts;
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
	struct ns_id *parent;
	struct list_head children;
	struct list_head siblings;
	struct ns_id *user_ns;
	struct ns_id *next;
	enum ns_type type;

	/*
	 * For mount namespaces on restore -- indicates that
	 * the namespace in question is created (all mounts
	 * are mounted) and other tasks may do setns on it
	 * and proceed.
	 */
	bool ns_populated;

	union {
		struct {
			struct mount_info *mntinfo_list;
			struct mount_info *mntinfo_tree;
			int ns_fd;
			int root_fd;
		} mnt;

		struct {
			int nsfd_id;	/* a namespace descriptor id in fdstore */
			int nlsk;	/* for sockets collection */
			int seqsk;	/* to talk to parasite daemons */
		} net;
		struct {
			UsernsEntry *e;
			int nsfd_id;
		} user;
	};
};
extern struct ns_id *ns_ids;
extern struct ns_id *root_user_ns;

#define NS_DESC_ENTRY(_cflag, _str)			\
	{						\
		.cflag		= _cflag,		\
		.str		= _str,			\
		.len		= sizeof(_str) - 1,	\
	}

extern bool check_ns_proc(struct fd_link *link);
extern unsigned int child_userns_xid(unsigned int xid, UidGidExtent **map, int n);

extern struct ns_desc pid_ns_desc;
extern struct ns_desc user_ns_desc;
extern struct ns_desc net_ns_desc;
extern unsigned long root_ns_mask;
extern UsernsEntry *userns_entry;

extern const struct fdtype_ops nsfile_dump_ops;
extern struct collect_image_info nsfile_cinfo;

extern int walk_namespaces(struct ns_desc *nd, int (*cb)(struct ns_id *, void *), void *oarg);
extern int collect_namespaces(bool for_dump);
extern int collect_mnt_namespaces(bool for_dump);
extern int dump_mnt_namespaces(void);
extern int dump_namespaces(struct pstree_item *item, unsigned int ns_flags);
extern int read_ns_with_hookups(void);
extern int set_ns_roots(void);
extern int prepare_namespace_before_tasks(void);
extern int prepare_namespace(struct pstree_item *item, unsigned long clone_flags);

extern int switch_ns(int pid, struct ns_desc *nd, int *rst);
extern int switch_ns_by_fd(int nsfd, struct ns_desc *nd, int *rst);
extern int restore_ns(int rst, struct ns_desc *nd);

extern int dump_task_ns_ids(struct pstree_item *);
extern int predump_task_ns_ids(struct pstree_item *);
extern struct ns_id *rst_new_ns_id(unsigned int id, pid_t pid, struct ns_desc *nd, enum ns_type t);
extern int rst_add_ns_id(unsigned int id, pid_t pid, struct ns_desc *nd);
extern struct ns_id *lookup_ns_by_id(unsigned int id, struct ns_desc *nd);

extern int collect_user_namespaces(bool for_dump);
extern int prepare_userns(pid_t real_pid, UsernsEntry *e);
extern int __set_user_ns(struct ns_id *ns);
extern int set_user_ns(u32 id);
extern int stop_usernsd(void);

extern uid_t userns_uid(uid_t uid);
extern gid_t userns_gid(gid_t gid);

extern unsigned int target_userns_uid(struct ns_id *ns, unsigned int uid);
extern unsigned int target_userns_gid(struct ns_id *ns, unsigned int gid);

extern unsigned int root_userns_uid(struct ns_id *ns, unsigned int uid);
extern unsigned int root_userns_gid(struct ns_id *ns, unsigned int gid);

extern void free_userns_maps(void);
extern int join_ns_add(const char *type, char *ns_file, char *extra_opts);
extern int check_namespace_opts(void);
extern int join_namespaces(void);

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
 * In case we're not in userns, just call the callback immediately
 * in the context of calling task.
 */
extern int __userns_call(const char *func_name, uns_call_t call, int flags,
			 void *arg, size_t arg_size, int fd);

#define userns_call(__call, __flags, __arg, __arg_size, __fd)	\
	__userns_call(__stringify(__call), __call, __flags,	\
		      __arg, __arg_size, __fd)

extern int add_ns_shared_cb(int (*actor)(void *data), void *data);

extern struct ns_id *get_socket_ns(int lfd);
extern struct ns_id *lookup_ns_by_kid(unsigned int kid, struct ns_desc *nd);

#endif /* __CR_NS_H__ */
