#ifndef __CR_PROC_PARSE_H__
#define __CR_PROC_PARSE_H__

#include <sys/types.h>
#include "asm/types.h"
#include "image.h"
#include "list.h"
#include "cgroup.h"

#include "protobuf/eventfd.pb-c.h"
#include "protobuf/eventpoll.pb-c.h"
#include "protobuf/signalfd.pb-c.h"
#include "protobuf/fsnotify.pb-c.h"
#include "protobuf/timerfd.pb-c.h"

#define PROC_TASK_COMM_LEN	32
#define PROC_TASK_COMM_LEN_FMT	"(%31s"

struct proc_pid_stat {
	int			pid;
	char			comm[PROC_TASK_COMM_LEN];
	char			state;
	int			ppid;
	int			pgid;
	int			sid;
	int			tty_nr;
	int			tty_pgrp;
	unsigned int		flags;
	unsigned long		min_flt;
	unsigned long		cmin_flt;
	unsigned long		maj_flt;
	unsigned long		cmaj_flt;
	unsigned long		utime;
	unsigned long		stime;
	long			cutime;
	long			cstime;
	long			priority;
	long			nice;
	int			num_threads;
	int			zero0;
	unsigned long long	start_time;
	unsigned long		vsize;
	long			mm_rss;
	unsigned long		rsslim;
	unsigned long		start_code;
	unsigned long		end_code;
	unsigned long		start_stack;
	unsigned long		esp;
	unsigned long		eip;
	unsigned long		sig_pending;
	unsigned long		sig_blocked;
	unsigned long		sig_ignored;
	unsigned long		sig_handled;
	unsigned long		wchan;
	unsigned long		zero1;
	unsigned long		zero2;
	int			exit_signal;
	int			task_cpu;
	unsigned int		rt_priority;
	unsigned int		policy;
	unsigned long long	delayacct_blkio_ticks;
	unsigned long		gtime;
	long			cgtime;
	unsigned long		start_data;
	unsigned long		end_data;
	unsigned long		start_brk;
	unsigned long		arg_start;
	unsigned long		arg_end;
	unsigned long		env_start;
	unsigned long		env_end;
	int			exit_code;
};

#define PROC_CAP_SIZE	2

struct proc_status_creds {
	unsigned int uids[4];
	unsigned int gids[4];

	u32 cap_inh[PROC_CAP_SIZE];
	u32 cap_prm[PROC_CAP_SIZE];
	u32 cap_eff[PROC_CAP_SIZE];
	u32 cap_bnd[PROC_CAP_SIZE];

	char			state;
	int			ppid;
};

struct mount_info;
struct fstype {
	char *name;
	int code;
	int (*dump)(struct mount_info *pm);
	int (*restore)(struct mount_info *pm);
	int (*parse)(struct mount_info *pm);
};

struct ext_mount;
struct mount_info {
	int		mnt_id;
	int		parent_mnt_id;
	unsigned int	s_dev;
	char		*root;
	/*
	 * During dump mountpoint contains path with dot at the 
	 * beginning. It allows to use openat, statat, etc without 
	 * creating a temporary copy of the path.
	 *
	 * On restore mountpoint is prepended with so called ns
	 * root path -- it's a place in fs where the namespace
	 * mount tree is constructed. Check mnt_roots for details.
	 * The ns_mountpoint contains path w/o this prefix.
	 */
	char		*mountpoint;
	char		*ns_mountpoint;
	unsigned	flags;
	int		master_id;
	int		shared_id;
	struct fstype	*fstype;
	char		*source;
	char		*options;
	union {
		bool		mounted;
		bool		dumped;
	};
	bool		need_plugin;
	int		is_file;
	bool		is_ns_root;
	struct mount_info *next;
	struct ns_id	*nsid;

	struct ext_mount *external;

	/* tree linkage */
	struct mount_info *parent;
	struct mount_info *bind;
	struct list_head children;
	struct list_head siblings;

	struct list_head mnt_bind;	/* circular list of derivatives of one real mount */
	struct list_head mnt_share;	/* circular list of shared mounts */
	struct list_head mnt_slave_list;/* list of slave mounts */
	struct list_head mnt_slave;	/* slave list entry */
	struct mount_info *mnt_master;	/* slave is on master->mnt_slave_list */

	struct list_head postpone;

	void		*private;	/* associated filesystem data */
};

extern struct mount_info *mnt_entry_alloc();
extern void mnt_entry_free(struct mount_info *mi);

struct vm_area_list;

extern struct mount_info *parse_mountinfo(pid_t pid, struct ns_id *nsid);
extern int parse_pid_stat(pid_t pid, struct proc_pid_stat *s);
extern int parse_smaps(pid_t pid, struct vm_area_list *vma_area_list, bool use_map_files);
extern int parse_self_maps_lite(struct vm_area_list *vms);
extern int parse_pid_status(pid_t pid, struct proc_status_creds *);

struct inotify_wd_entry {
	InotifyWdEntry e;
	FhEntry f_handle;
	struct list_head node;
};

struct fanotify_mark_entry {
	FanotifyMarkEntry e;
	FhEntry f_handle;
	struct list_head node;
	union {
		FanotifyInodeMarkEntry ie;
		FanotifyMountMarkEntry me;
	};
};

struct eventpoll_tfd_entry {
	EventpollTfdEntry e;
	struct list_head node;
};

union fdinfo_entries {
	EventfdFileEntry efd;
	SignalfdEntry sfd;
	struct inotify_wd_entry ify;
	struct fanotify_mark_entry ffy;
	struct eventpoll_tfd_entry epl;
	TimerfdEntry tfy;
};

extern void free_inotify_wd_entry(union fdinfo_entries *e);
extern void free_fanotify_mark_entry(union fdinfo_entries *e);
extern void free_event_poll_entry(union fdinfo_entries *e);

struct fdinfo_common {
	off64_t pos;
	int flags;
	int mnt_id;
};

extern int parse_fdinfo(int fd, int type,
		int (*cb)(union fdinfo_entries *e, void *arg), void *arg);
extern int parse_fdinfo_pid(int pid, int fd, int type,
		int (*cb)(union fdinfo_entries *e, void *arg), void *arg);
extern int parse_cpuinfo_features(int (*handler)(char *tok));
extern int parse_file_locks(void);
extern int get_fd_mntid(int fd, int *mnt_id);

struct pid;
extern int parse_threads(int pid, struct pid **_t, int *_n);

extern int check_mnt_id(void);

/*
 * This struct describes a group controlled by one controller.
 * The @name is the controller name or 'name=...' for named cgroups.
 * The @path is the path from the hierarchy root.
 */

struct cg_ctl {
	struct list_head l;
	char *name;
	char *path;
};

/*
 * Returns the list of cg_ctl-s sorted by name
 */

extern int parse_task_cgroup(int pid, struct list_head *l, unsigned int *n);
extern void put_ctls(struct list_head *);

int parse_cgroups(struct list_head *cgroups, unsigned int *n_cgroups);

/* callback for AUFS support */
extern int aufs_parse(struct mount_info *mi);

#endif /* __CR_PROC_PARSE_H__ */
