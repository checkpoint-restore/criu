#ifndef PARASITE_SYSCALL_H_
#define PARASITE_SYSCALL_H_

#define BUILTIN_SYSCALL_SIZE	8

/* parasite control block */
struct parasite_ctl {
	pid_t			pid;					/* process pid where we live in */
	void *			remote_map;
	void *			local_map;
	unsigned long		map_length;

	unsigned long		parasite_ip;				/* service routine start ip */
	user_regs_struct_t	regs_orig;				/* original registers */
	unsigned long		syscall_ip;				/* entry point of infection */
	u8			code_orig[BUILTIN_SYSCALL_SIZE];

	int			signals_blocked;

	void *			addr_cmd;				/* addr for command */
	void *			addr_args;				/* address for arguments */
	int			tsock;					/* transport socket for transfering fds */
};

struct cr_fdset;
struct list_head;

extern int parasite_dump_sigacts_seized(struct parasite_ctl *ctl, struct cr_fdset *cr_fdset);
extern int parasite_dump_itimers_seized(struct parasite_ctl *ctl, struct cr_fdset *cr_fdset);

struct parasite_dump_misc;
extern int parasite_dump_misc_seized(struct parasite_ctl *ctl, struct parasite_dump_misc *misc);
extern int parasite_dump_pages_seized(struct parasite_ctl *ctl,
				      struct list_head *vma_area_list,
				      struct cr_fdset *cr_fdset);
struct parasite_dump_tid_info;
extern int parasite_dump_thread_seized(struct parasite_ctl *ctl, pid_t pid,
					unsigned int **tid_add, u32 *tid);

extern int parasite_drain_fds_seized(struct parasite_ctl *ctl, int *fds, int *lfds, int nr_fds, char *flags);

extern int parasite_cure_seized(struct parasite_ctl *ctl);
extern struct parasite_ctl *parasite_infect_seized(pid_t pid,
						   struct list_head *vma_area_list);

#endif /* PARASITE_SYSCALL_H_ */
