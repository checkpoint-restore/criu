#ifndef PARASITE_SYSCALL_H_
#define PARASITE_SYSCALL_H_

#include <sys/types.h>
#include <sys/mman.h>

#include "compiler.h"
#include "types.h"
#include "list.h"
#include "crtools.h"

#define BUILTIN_SYSCALL_SIZE	8

/* parasite control block */
struct parasite_ctl {
	pid_t			pid;			/* process pid where we live in */
	struct vma_area		vma_area;		/* our space we host */
	unsigned long		parasite_ip;		/* service routine start ip */
	unsigned long		addr_cmd;		/* addr for command */
	unsigned long		addr_args;		/* address for arguments */
};

extern int can_run_syscall(unsigned long ip, unsigned long start, unsigned long end);

extern void *mmap_seized(pid_t pid, user_regs_struct_t *regs,
			 void *addr, size_t length, int prot,
			 int flags, int fd, off_t offset);

extern int munmap_seized(pid_t pid, user_regs_struct_t *regs,
			 void *addr, size_t length);

extern int syscall_seized(pid_t pid,
			  user_regs_struct_t *where,
			  user_regs_struct_t *params,
			  user_regs_struct_t *result);

extern int parasite_dump_pages_seized(struct parasite_ctl *ctl, struct list_head *vma_area_list,
			       struct cr_fdset *cr_fdset);
extern int parasite_dump_sigacts_seized(struct parasite_ctl *ctl, struct cr_fdset *cr_fdset);
extern int parasite_dump_itimers_seized(struct parasite_ctl *ctl, struct cr_fdset *cr_fdset);

struct parasite_dump_misc;
extern int parasite_dump_misc_seized(struct parasite_ctl *ctl, struct parasite_dump_misc *);

extern struct parasite_ctl *parasite_infect_seized(pid_t pid, struct list_head *vma_area_list);
extern int parasite_cure_seized(struct parasite_ctl *ctl, struct list_head *vma_area_list);

#endif /* PARASITE_SYSCALL_H_ */
