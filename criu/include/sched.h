#ifndef __CR_SCHED_H__
#define __CR_SCHED_H__

#include <linux/types.h>

#ifndef ptr_to_u64
#define ptr_to_u64(ptr) ((__u64)((uintptr_t)(ptr)))
#endif
#ifndef u64_to_ptr
#define u64_to_ptr(x) ((void *)(uintptr_t)x)
#endif

/*
 * This structure is needed by clone3(). The kernel
 * calls it 'struct clone_args'. As CRIU will always
 * need at least this part of the structure (VER1)
 * to be able to test if clone3() with set_tid works,
 * the structure is defined here as 'struct _clone_args'.
 */

struct _clone_args {
	__aligned_u64 flags;
	__aligned_u64 pidfd;
	__aligned_u64 child_tid;
	__aligned_u64 parent_tid;
	__aligned_u64 exit_signal;
	__aligned_u64 stack;
	__aligned_u64 stack_size;
	__aligned_u64 tls;
	__aligned_u64 set_tid;
	__aligned_u64 set_tid_size;
};
#endif /* __CR_SCHED_H__ */
