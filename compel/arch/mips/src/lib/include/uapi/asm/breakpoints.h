#ifndef __COMPEL_BREAKPOINTS_H__
#define __COMPEL_BREAKPOINTS_H__
#define ARCH_SI_TRAP TRAP_BRKPT
extern int ptrace_set_breakpoint(pid_t pid, void *addr);
extern int ptrace_flush_breakpoints(pid_t pid);
#endif
