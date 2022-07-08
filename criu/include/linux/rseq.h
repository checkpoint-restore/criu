/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_RSEQ_H
#define _UAPI_LINUX_RSEQ_H

#ifdef __has_include
#if __has_include("sys/rseq.h")
#include <sys/rseq.h>
#include "asm/thread_pointer.h"
#endif
#endif

#include <linux/types.h>
#include <asm/byteorder.h>

#include "common/config.h"

#ifdef CONFIG_HAS_NO_LIBC_RSEQ_DEFS
/*
 * linux/rseq.h
 *
 * Restartable sequences system call API
 *
 * Copyright (c) 2015-2018 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

enum rseq_cpu_id_state {
	RSEQ_CPU_ID_UNINITIALIZED = -1,
	RSEQ_CPU_ID_REGISTRATION_FAILED = -2,
};

enum rseq_flags {
	RSEQ_FLAG_UNREGISTER = (1 << 0),
};

enum rseq_cs_flags_bit {
	RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT_BIT = 0,
	RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL_BIT = 1,
	RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE_BIT = 2,
};

enum rseq_cs_flags {
	RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT = (1U << RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT_BIT),
	RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL = (1U << RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL_BIT),
	RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE = (1U << RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE_BIT),
};
#endif /* CONFIG_HAS_NO_LIBC_RSEQ_DEFS */

/*
 * Let's use our own definition of struct rseq_cs because some distros
 * (for example Mariner GNU/Linux) declares this structure their-own way.
 * This makes trouble with inconsistency between printf formatters and
 * struct rseq_cs field types.
 */
/*
 * struct rseq_cs is aligned on 4 * 8 bytes to ensure it is always
 * contained within a single cache-line. It is usually declared as
 * link-time constant data.
 */
struct criu_rseq_cs {
	/* Version of this structure. */
	__u32 version;
	/* enum rseq_cs_flags */
	__u32 flags;
	__u64 start_ip;
	/* Offset from start_ip. */
	__u64 post_commit_offset;
	__u64 abort_ip;
} __attribute__((aligned(4 * sizeof(__u64))));

/*
 * We have to have our own copy of struct rseq definition because
 * of breaking UAPI change:
 * https://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git/commit/?id=bfdf4e6208051ed7165b2e92035b4bf11f43eb63
 */
/*
 * struct rseq is aligned on 4 * 8 bytes to ensure it is always
 * contained within a single cache-line.
 *
 * A single struct rseq per thread is allowed.
 */
struct criu_rseq {
	/*
	 * Restartable sequences cpu_id_start field. Updated by the
	 * kernel. Read by user-space with single-copy atomicity
	 * semantics. This field should only be read by the thread which
	 * registered this data structure. Aligned on 32-bit. Always
	 * contains a value in the range of possible CPUs, although the
	 * value may not be the actual current CPU (e.g. if rseq is not
	 * initialized). This CPU number value should always be compared
	 * against the value of the cpu_id field before performing a rseq
	 * commit or returning a value read from a data structure indexed
	 * using the cpu_id_start value.
	 */
	__u32 cpu_id_start;
	/*
	 * Restartable sequences cpu_id field. Updated by the kernel.
	 * Read by user-space with single-copy atomicity semantics. This
	 * field should only be read by the thread which registered this
	 * data structure. Aligned on 32-bit. Values
	 * RSEQ_CPU_ID_UNINITIALIZED and RSEQ_CPU_ID_REGISTRATION_FAILED
	 * have a special semantic: the former means "rseq uninitialized",
	 * and latter means "rseq initialization failed". This value is
	 * meant to be read within rseq critical sections and compared
	 * with the cpu_id_start value previously read, before performing
	 * the commit instruction, or read and compared with the
	 * cpu_id_start value before returning a value loaded from a data
	 * structure indexed using the cpu_id_start value.
	 */
	__u32 cpu_id;
	/*
	 * Restartable sequences rseq_cs field.
	 *
	 * Contains NULL when no critical section is active for the current
	 * thread, or holds a pointer to the currently active struct rseq_cs.
	 *
	 * Updated by user-space, which sets the address of the currently
	 * active rseq_cs at the beginning of assembly instruction sequence
	 * block, and set to NULL by the kernel when it restarts an assembly
	 * instruction sequence block, as well as when the kernel detects that
	 * it is preempting or delivering a signal outside of the range
	 * targeted by the rseq_cs. Also needs to be set to NULL by user-space
	 * before reclaiming memory that contains the targeted struct rseq_cs.
	 *
	 * Read and set by the kernel. Set by user-space with single-copy
	 * atomicity semantics. This field should only be updated by the
	 * thread which registered this data structure. Aligned on 64-bit.
	 *
	 * 32-bit architectures should update the low order bits of the
	 * rseq_cs field, leaving the high order bits initialized to 0.
	 */
	__u64 rseq_cs;

	/*
	 * Restartable sequences flags field.
	 *
	 * This field should only be updated by the thread which
	 * registered this data structure. Read by the kernel.
	 * Mainly used for single-stepping through rseq critical sections
	 * with debuggers.
	 *
	 * - RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT
	 *     Inhibit instruction sequence block restart on preemption
	 *     for this thread.
	 * - RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL
	 *     Inhibit instruction sequence block restart on signal
	 *     delivery for this thread.
	 * - RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE
	 *     Inhibit instruction sequence block restart on migration for
	 *     this thread.
	 */
	__u32 flags;
} __attribute__((aligned(4 * sizeof(__u64))));

#endif /* _UAPI_LINUX_RSEQ_H */
