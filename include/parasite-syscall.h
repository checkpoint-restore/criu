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
	pid_t			pid;			/* process where we live */
	struct vma_area		*vma_area;		/* our space */
	unsigned long		parasite_ip;		/* service routine start ip */
	unsigned long		parasite_complete_ip;	/* where we end execution */
	unsigned long		addr_cmd;		/* addr for command */
	unsigned long		addr_args;		/* address for arguments */
};

int can_run_syscall(unsigned long ip, unsigned long start, unsigned long end);

void *mmap_seized(pid_t pid, user_regs_struct_t *regs,
		  void *addr, size_t length, int prot,
		  int flags, int fd, off_t offset);

int munmap_seized(pid_t pid, user_regs_struct_t *regs,
		  void *addr, size_t length);
int kill_seized(pid_t pid, user_regs_struct_t *where);
unsigned long brk_seized(pid_t pid, unsigned long addr);

int syscall_seized(pid_t pid,
		   user_regs_struct_t *where,
		   user_regs_struct_t *params,
		   user_regs_struct_t *result);

int parasite_dump_pages_seized(struct parasite_ctl *ctl, struct list_head *vma_area_list,
			       struct cr_fdset *cr_fdset, int fd_type);

struct parasite_ctl *parasite_infect_seized(pid_t pid, void *addr_hint, struct list_head *vma_area_list);
int parasite_cure_seized(struct parasite_ctl **p_ctrl, struct list_head *vma_area_list);

#endif /* PARASITE_SYSCALL_H_ */
