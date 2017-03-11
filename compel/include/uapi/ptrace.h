#ifndef UAPI_COMPEL_PTRACE_H__
#define UAPI_COMPEL_PTRACE_H__

/*
 * We'd want to include both sys/ptrace.h and linux/ptrace.h,
 * hoping that most definitions come from either one or another.
 * Alas, on Alpine/musl both files declare struct ptrace_peeksiginfo_args,
 * so there is no way they can be used together. Let's rely on libc one.
 */
#include <sys/ptrace.h>

#include <compel/asm/breakpoints.h>

/*
 * Some constants for ptrace that might be missing from the
 * standard library includes due to being (relatively) new.
 */

#ifndef PTRACE_SEIZE
# define PTRACE_SEIZE		0x4206
#endif

#ifndef PTRACE_O_SUSPEND_SECCOMP
# define PTRACE_O_SUSPEND_SECCOMP (1 << 21)
#endif

#ifndef PTRACE_INTERRUPT
# define PTRACE_INTERRUPT	0x4207
#endif

#ifndef PTRACE_PEEKSIGINFO
#define PTRACE_PEEKSIGINFO      0x4209

/* Read signals from a shared (process wide) queue */
#define PTRACE_PEEKSIGINFO_SHARED       (1 << 0)
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

#ifdef PTRACE_EVENT_STOP
# if PTRACE_EVENT_STOP == 7 /* Bad value from Linux 3.1-3.3, fixed in 3.4 */
#  undef PTRACE_EVENT_STOP
# endif
#endif
#ifndef PTRACE_EVENT_STOP
# define PTRACE_EVENT_STOP	128
#endif

extern int ptrace_suspend_seccomp(pid_t pid);

#endif /* UAPI_COMPEL_PTRACE_H__ */
