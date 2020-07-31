#ifndef __CR_PROC_PARSE_H__
#define __CR_PROC_PARSE_H__

#include <sys/types.h>

#include "compel/infect.h"

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
	struct seize_task_status s;

	unsigned int uids[4];
	unsigned int gids[4];

	u32			last_filter;

	/*
	 * Keep them at the end of structure
	 * for fast comparison reason.
	 */
	u32			cap_inh[PROC_CAP_SIZE];
	u32			cap_prm[PROC_CAP_SIZE];
	u32			cap_eff[PROC_CAP_SIZE];
	u32			cap_bnd[PROC_CAP_SIZE];
};

#define INVALID_UID ((uid_t)-1)

extern int parse_pid_stat(pid_t pid, struct proc_pid_stat *s);
extern unsigned int parse_pid_loginuid(pid_t pid, int *err, bool ignore_noent);
extern int parse_pid_oom_score_adj(pid_t pid, int *err);
extern int prepare_loginuid(unsigned int value);
extern int parse_pid_status(pid_t pid, struct seize_task_status *, void *data);
extern int parse_file_locks(void);
extern int get_fd_mntid(int fd, int *mnt_id);

struct pid;
extern int parse_threads(int pid, struct pid **_t, int *_n);

int parse_children(pid_t pid, pid_t **_c, int *_n);

extern bool is_vma_range_fmt(char *line);
extern void parse_vmflags(char *buf, u32 *flags, u64 *madv, int *io_pf);
extern int parse_uptime(uint64_t *upt);

extern int parse_timens_offsets(struct timespec *boff, struct timespec *moff);

#endif /* __CR_PROC_PARSE_H__ */
