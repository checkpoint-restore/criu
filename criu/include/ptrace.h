#ifndef __CR_PTRACE_H__
#define __CR_PTRACE_H__

#include <linux/types.h>
#include <sys/ptrace.h>

#include "config.h"
#include "proc_parse.h"

/* some constants for ptrace */
#ifndef PTRACE_SEIZE
# define PTRACE_SEIZE		0x4206
#endif

#ifndef PTRACE_O_SUSPEND_SECCOMP
# define PTRACE_O_SUSPEND_SECCOMP (1 << 21)
#endif

#ifndef PTRACE_INTERRUPT
# define PTRACE_INTERRUPT	0x4207
#endif

#ifndef PTRACE_LISTEN
#define PTRACE_LISTEN		0x4208
#endif

#ifndef PTRACE_PEEKSIGINFO
#define PTRACE_PEEKSIGINFO      0x4209

/* Read signals from a shared (process wide) queue */
#define PTRACE_PEEKSIGINFO_SHARED       (1 << 0)
#endif

#ifndef CONFIG_HAS_PTRACE_PEEKSIGINFO
struct ptrace_peeksiginfo_args {
        __u64 off;	/* from which siginfo to start */
        __u32 flags;
        __u32 nr;	/* how may siginfos to take */
};
#endif

#ifndef PTRACE_GETREGSET
# define PTRACE_GETREGSET	0x4204
# define PTRACE_SETREGSET	0x4205
#endif

#ifndef PTRACE_GETSIGMASK
# define PTRACE_GETSIGMASK	0x420a
# define PTRACE_SETSIGMASK	0x420b
#endif

#ifndef PTRACE_SECCOMP_GET_FILTER
#define PTRACE_SECCOMP_GET_FILTER	0x420c
#endif

#define PTRACE_SEIZE_DEVEL	0x80000000

#define PTRACE_EVENT_FORK	1
#define PTRACE_EVENT_VFORK	2
#define PTRACE_EVENT_CLONE	3
#define PTRACE_EVENT_EXEC	4
#define PTRACE_EVENT_VFORK_DONE	5
#define PTRACE_EVENT_EXIT	6
#define PTRACE_EVENT_STOP	128

#define PTRACE_O_TRACESYSGOOD	0x00000001
#define PTRACE_O_TRACEFORK	0x00000002
#define PTRACE_O_TRACEVFORK	0x00000004
#define PTRACE_O_TRACECLONE	0x00000008
#define PTRACE_O_TRACEEXEC	0x00000010
#define PTRACE_O_TRACEVFORKDONE	0x00000020
#define PTRACE_O_TRACEEXIT	0x00000040

#define SI_EVENT(_si_code)	(((_si_code) & 0xFFFF) >> 8)

extern int seize_catch_task(pid_t pid);
extern int seize_wait_task(pid_t pid, pid_t ppid, struct proc_status_creds *creds);
extern int suspend_seccomp(pid_t pid);
extern int unseize_task(pid_t pid, int orig_state, int state);
extern int ptrace_peek_area(pid_t pid, void *dst, void *addr, long bytes);
extern int ptrace_poke_area(pid_t pid, void *src, void *addr, long bytes);
extern int ptrace_swap_area(pid_t pid, void *dst, void *src, long bytes);

#endif /* __CR_PTRACE_H__ */
