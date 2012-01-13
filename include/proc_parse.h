#ifndef __PROC_PARSE_H__
#define __PROC_PARSE_H__
int parse_maps(pid_t pid, int pid_dir, struct list_head *vma_area_list, bool use_map_files);

#define TASK_COMM_LEN 16

struct proc_pid_stat {
	int pid;
	char comm[TASK_COMM_LEN];
	char state;
	int ppid;
	int pgid;
	int sid;
	int tty_nr;
	int tty_pgrp;
	unsigned int flags;
	unsigned long min_flt;
	unsigned long cmin_flt;
	unsigned long maj_flt;
	unsigned long cmaj_flt;
	unsigned long utime;
	unsigned long stime;
	long cutime;
	long cstime;
	long priority;
	long nice;
	int num_threads;
	int zero0;
	unsigned long long start_time;
	unsigned long vsize;
	long mm_rss;
	unsigned long rsslim;
	unsigned long start_code;
	unsigned long end_code;
	unsigned long start_stack;
	unsigned long esp;
	unsigned long eip;
	unsigned long sig_pending;
	unsigned long sig_blocked;
	unsigned long sig_ignored;
	unsigned long sig_handled;
	unsigned long wchan;
	unsigned long zero1;
	unsigned long zero2;
	int exit_signal;
	int task_cpu;
	unsigned int rt_priority;
	unsigned int policy;
	unsigned long long delayacct_blkio_ticks;
	unsigned long gtime;
	long cgtime;
	unsigned long start_data;
	unsigned long end_data;
	unsigned long start_brk;
};

int parse_pid_stat(pid_t pid, int pid_dir, struct proc_pid_stat *s);
#endif
