#ifndef COMPEL_PTRACE_H__
#define COMPEL_PTRACE_H__

#include <compel/asm/infect-types.h>
#include <compel/ptrace.h>
#include <linux/types.h>

#define PTRACE_SI_EVENT(_si_code) (((_si_code)&0xFFFF) >> 8)

extern int ptrace_get_regs(pid_t pid, user_regs_struct_t *regs);
extern int ptrace_set_regs(pid_t pid, user_regs_struct_t *regs);

#endif /* COMPEL_PTRACE_H__ */
