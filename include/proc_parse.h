#ifndef __CR_PROC_PARSE_H__
#define __CR_PROC_PARSE_H__

#include <sys/types.h>
#include "asm/types.h"
#include "restorer.h"
#include "image.h"
#include "list.h"

#include "protobuf/eventfd.pb-c.h"
#include "protobuf/eventpoll.pb-c.h"
#include "protobuf/signalfd.pb-c.h"
#include "protobuf/fsnotify.pb-c.h"

#define PROC_TASK_COMM_LEN	32
#define PROC_TASK_COMM_LEN_FMT	"(%31s"

struct proc_pid_stat_small {
	int			pid;
	char			comm[PROC_TASK_COMM_LEN];
	char			state;
	int			ppid;
	int			pgid;
	int			sid;
};

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

	uint32_t cap_inh[PROC_CAP_SIZE];
	uint32_t cap_prm[PROC_CAP_SIZE];
	uint32_t cap_eff[PROC_CAP_SIZE];
	uint32_t cap_bnd[PROC_CAP_SIZE];
};

struct mount_info;
struct fstype {
	char *name;
	int (*dump)(struct mount_info *pm);
	int (*restore)(struct mount_info *pm);
};

struct mount_info {
	int		mnt_id;
	int		parent_mnt_id;
	unsigned int	s_dev;
	char		*root;
	char		*mountpoint;
	unsigned	flags;
	int		master_id;
	int		shared_id;
	struct fstype	*fstype;
	char		*source;
	char		*options;
	bool		mounted;
	struct mount_info *next;

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
};

struct proc_posix_timer {
	struct list_head list;
	struct str_posix_timer spt;
};

struct proc_posix_timers_stat {
	int timer_n;
	struct list_head timers;
};

extern struct mount_info *mnt_entry_alloc();
extern void mnt_entry_free(struct mount_info *mi);

struct vm_area_list;

extern struct mount_info *parse_mountinfo(pid_t pid);
extern int parse_pid_stat(pid_t pid, struct proc_pid_stat *s);
extern int parse_pid_stat_small(pid_t pid, struct proc_pid_stat_small *s);
extern int parse_smaps(pid_t pid, struct vm_area_list *vma_area_list, bool use_map_files);
extern int parse_pid_status(pid_t pid, struct proc_status_creds *);

union fdinfo_entries {
	EventfdFileEntry efd;
	EventpollTfdEntry epl;
	SignalfdEntry sfd;
	InotifyWdEntry ify;
	FanotifyMarkEntry ffy;
};

extern int parse_fdinfo(int fd, int type,
		int (*cb)(union fdinfo_entries *e, void *arg), void *arg);
extern int parse_cpuinfo_features(int (*handler)(char *tok));
extern int parse_file_locks(void);

extern int parse_posix_timers(pid_t pid, struct proc_posix_timers_stat * args);

#endif /* __CR_PROC_PARSE_H__ */
