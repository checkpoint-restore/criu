#ifndef __COMPEL_BREAKPOINTS_H__
#define __COMPEL_BREAKPOINTS_H__
#define ARCH_SI_TRAP TRAP_BRKPT

#include <sys/types.h>
#include <stdbool.h>

int ptrace_set_breakpoint(pid_t pid, void *addr);
int ptrace_flush_breakpoints(pid_t pid, bool restore);

#endif
