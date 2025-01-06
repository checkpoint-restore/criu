#ifndef __COMPEL_BREAKPOINTS_H__
#define __COMPEL_BREAKPOINTS_H__
#define ARCH_SI_TRAP TRAP_BRKPT

#include <sys/types.h>
#include <stdbool.h>

struct hwbp_cap {
	char arch;
	char bp_count;
};

/* copied from `linux/arch/arm64/include/asm/hw_breakpoint.h` */
/* Lengths */
#define ARM_BREAKPOINT_LEN_1 0x1
#define ARM_BREAKPOINT_LEN_2 0x3
#define ARM_BREAKPOINT_LEN_3 0x7
#define ARM_BREAKPOINT_LEN_4 0xf
#define ARM_BREAKPOINT_LEN_5 0x1f
#define ARM_BREAKPOINT_LEN_6 0x3f
#define ARM_BREAKPOINT_LEN_7 0x7f
#define ARM_BREAKPOINT_LEN_8 0xff

/* Privilege Levels */
#define AARCH64_BREAKPOINT_EL1 1
#define AARCH64_BREAKPOINT_EL0 2

/* Breakpoint */
#define ARM_BREAKPOINT_EXECUTE 0

/* Watchpoints */
#define ARM_BREAKPOINT_LOAD	1
#define ARM_BREAKPOINT_STORE	2
#define AARCH64_ESR_ACCESS_MASK (1 << 6)

#define DISABLE_HBP 0
#define ENABLE_HBP  1

int ptrace_set_breakpoint(pid_t pid, void *addr);
int ptrace_flush_breakpoints(pid_t pid);

#endif
