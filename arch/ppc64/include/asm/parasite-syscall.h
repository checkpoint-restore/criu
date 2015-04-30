#ifndef __CR_ASM_PARASITE_SYSCALL_H__
#define __CR_ASM_PARASITE_SYSCALL_H__

struct parasite_ctl;

#define ARCH_SI_TRAP TRAP_BRKPT

extern const char code_syscall[];
extern const int code_syscall_size;

void parasite_setup_regs(unsigned long new_ip, void *stack, user_regs_struct_t *regs);

void *mmap_seized(struct parasite_ctl *ctl,
		  void *addr, size_t length, int prot,
		  int flags, int fd, off_t offset);

#endif
