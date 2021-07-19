/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1998, 1999, 2001, 2003 Ralf Baechle
 * Copyright (C) 2000, 2001 Silicon Graphics, Inc.
 */
#ifndef _UAPI_ASM_SIGINFO_H
#define _UAPI_ASM_SIGINFO_H

#define __ARCH_SIGEV_PREAMBLE_SIZE (sizeof(long) + 2 * sizeof(int))
#undef __ARCH_SI_TRAPNO /* exception code needs to fill this ...  */

#define HAVE_ARCH_SIGINFO_T

/*
 * Careful to keep union _sifields from shifting ...
 */

#define __ARCH_SI_PREAMBLE_SIZE (4 * sizeof(int))

#define __ARCH_SIGSYS

#define SI_MAX_SIZE	128
#define SI_PAD_SIZE	((SI_MAX_SIZE - __ARCH_SI_PREAMBLE_SIZE) / sizeof(int))
#define __ARCH_SI_UID_T __kernel_uid32_t

#ifndef __ARCH_SI_UID_T
#define __ARCH_SI_UID_T __kernel_uid32_t
#endif

#ifndef __ARCH_SI_BAND_T
#define __ARCH_SI_BAND_T long
#endif

#ifndef __ARCH_SI_CLOCK_T
#define __ARCH_SI_CLOCK_T __kernel_clock_t
#endif

#ifndef __ARCH_SI_ATTRIBUTES
#define __ARCH_SI_ATTRIBUTES
#endif

typedef struct siginfo {
	int si_signo;
	int si_errno;
	int si_code;

	union {
		int _pad[SI_PAD_SIZE];

		/* kill() */
		struct {
			__kernel_pid_t _pid; /* sender's pid */
			__ARCH_SI_UID_T _uid; /* sender's uid */
		} _kill;

		/* POSIX.1b timers */
		struct {
			__kernel_timer_t _tid; /* timer id */
			int _overrun; /* overrun count */
			char _pad[sizeof(__ARCH_SI_UID_T) - sizeof(int)];
			sigval_t _sigval; /* same as below */
			int _sys_private; /* not to be passed to user */
		} _timer;

		/* POSIX.1b signals */
		struct {
			__kernel_pid_t _pid; /* sender's pid */
			__ARCH_SI_UID_T _uid; /* sender's uid */
			sigval_t _sigval;
		} _rt;

		/* SIGCHLD */
		struct {
			__kernel_pid_t _pid; /* which child */
			__ARCH_SI_UID_T _uid; /* sender's uid */
			int _status; /* exit code */
			__ARCH_SI_CLOCK_T _utime;
			__ARCH_SI_CLOCK_T _stime;
		} _sigchld;

		/* SIGILL, SIGFPE, SIGSEGV, SIGBUS */
		struct {
			void *_addr; /* faulting insn/memory ref. */
#ifdef __ARCH_SI_TRAPNO
			int _trapno; /* TRAP # which caused the signal */
#endif
			short _addr_lsb; /* LSB of the reported address */
#ifndef __GENKSYMS__
			struct {
				void *_lower;
				void *_upper;
			} _addr_bnd;
#endif
		} _sigfault;

		/* SIGPOLL */
		struct {
			__ARCH_SI_BAND_T _band; /* POLL_IN, POLL_OUT, POLL_MSG */
			int _fd;
		} _sigpoll;

		/* SIGSYS */
		struct {
			void *_call_addr; /* calling user insn */
			int _syscall; /* triggering system call number */
			unsigned int _arch; /* AUDIT_ARCH_* of syscall */
		} _sigsys;
	} _sifields;
} __ARCH_SI_ATTRIBUTES siginfo_t;

/*
 * si_code values
 * Again these have been chosen to be IRIX compatible.
 */
#undef SI_ASYNCIO
#undef SI_TIMER
#undef SI_MESGQ
#define SI_ASYNCIO -2 /* sent by AIO completion */

#endif /* _UAPI_ASM_SIGINFO_H */
