#ifndef UAPI_COMPEL_PTRACE_H__
#define UAPI_COMPEL_PTRACE_H__

#include "common/compiler.h"
/*
 * We'd want to include both sys/ptrace.h and linux/ptrace.h,
 * hoping that most definitions come from either one or another.
 * Alas, on Alpine/musl both files declare struct ptrace_peeksiginfo_args,
 * so there is no way they can be used together. Let's rely on libc one.
 */
#include <sys/ptrace.h>
#include <stdint.h>

#include <compel/asm/breakpoints.h>

/*
 * Some constants for ptrace that might be missing from the
 * standard library includes due to being (relatively) new.
 */

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif

#ifndef PTRACE_O_SUSPEND_SECCOMP
#define PTRACE_O_SUSPEND_SECCOMP (1 << 21)
#endif

#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif

#ifndef PTRACE_PEEKSIGINFO
#define PTRACE_PEEKSIGINFO 0x4209

/* Read signals from a shared (process wide) queue */
#define PTRACE_PEEKSIGINFO_SHARED (1 << 0)
#endif

#ifndef PTRACE_GETREGSET
#define PTRACE_GETREGSET 0x4204
#define PTRACE_SETREGSET 0x4205
#endif

#ifndef PTRACE_GETSIGMASK
#define PTRACE_GETSIGMASK 0x420a
#define PTRACE_SETSIGMASK 0x420b
#endif

#ifndef PTRACE_SECCOMP_GET_FILTER
#define PTRACE_SECCOMP_GET_FILTER 0x420c
#endif

#ifndef PTRACE_SECCOMP_GET_METADATA
#define PTRACE_SECCOMP_GET_METADATA 0x420d
#endif /* PTRACE_SECCOMP_GET_METADATA */

/*
 * struct seccomp_metadata is not yet
 * settled down well in headers so use
 * own identical definition for a while.
 */
typedef struct {
	uint64_t filter_off; /* Input: which filter */
	uint64_t flags;	     /* Output: filter's flags */
} seccomp_metadata_t;

#ifndef PTRACE_GET_RSEQ_CONFIGURATION
#define PTRACE_GET_RSEQ_CONFIGURATION 0x420f

struct __ptrace_rseq_configuration {
	uint64_t rseq_abi_pointer;
	uint32_t rseq_abi_size;
	uint32_t signature;
	uint32_t flags;
	uint32_t pad;
};
#endif

#ifdef PTRACE_EVENT_STOP
#if PTRACE_EVENT_STOP == 7 /* Bad value from Linux 3.1-3.3, fixed in 3.4 */
#undef PTRACE_EVENT_STOP
#endif
#endif
#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

/*
 * Amazon Linux 2 uses glibc 2.26. PTRACE_ARCH_PRCTL was added in glibc 2.27.
 * This allows CRIU to build on Amazon Linux 2.
 *
 * Note that in sys/ptrace.h, PTRACE_ARCH_PRCTL is an enum value so the
 * preprocessor doesn't know about it. PT_ARCH_PRCTL is the preprocessor symbol
 * that matches the value of PTRACE_ARCH_PRCTL. So look for PT_ARCH_PRCTL to
 * decide if PTRACE_ARCH_PRCTL is available or not.
 */
#if defined(__x86_64__) && !defined(PT_ARCH_PRCTL)
#define PTRACE_ARCH_PRCTL 30 /* From asm/ptrace-abi.h. */
#endif

extern int ptrace_suspend_seccomp(pid_t pid);

extern int __must_check ptrace_peek_area(pid_t pid, void *dst, void *addr, long bytes);
extern int __must_check ptrace_poke_area(pid_t pid, void *src, void *addr, long bytes);
extern int __must_check ptrace_swap_area(pid_t pid, void *dst, void *src, long bytes);

#endif /* UAPI_COMPEL_PTRACE_H__ */
