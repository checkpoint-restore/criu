#include <stdlib.h>
#include <sched.h>
#include <unistd.h>

#include <compel/plugins/std/syscall-codes.h>

#include "sched.h"
#include "common/compiler.h"
#include "log.h"
#include "common/bug.h"

/*
 * ASan doesn't play nicely with clone if we use current stack for
 * child task. ASan puts local variables on the fake stack
 * to catch use-after-return bug:
 *         https://github.com/google/sanitizers/wiki/AddressSanitizerUseAfterReturn#algorithm
 *
 * So it's become easy to overflow this fake stack frame in cloned child.
 * We need a real stack for clone().
 *
 * To workaround this we add clone_noasan() not-instrumented wrapper for
 * clone(). Unfortunately we can't use __attribute__((no_sanitize_address))
 * for this because of bug in GCC > 6:
 *         https://gcc.gnu.org/bugzilla/show_bug.cgi?id=69863
 *
 * So the only way is to put this wrapper in separate non-instrumented file
 *
 * WARNING: When calling clone_noasan make sure your not sitting in a later
 * __restore__ phase where other tasks might be creating threads, otherwise
 * all calls to clone_noasan should be guarder with
 *
 * 	lock_last_pid
 *	clone_noasan
 *	... wait for process to finish ...
 *	unlock_last_pid
 */
int clone_noasan(int (*fn)(void *), int flags, void *arg)
{
	void *stack_ptr = (void *)round_down((unsigned long)&stack_ptr - 1024, 16);

	BUG_ON((flags & CLONE_VM) && !(flags & CLONE_VFORK));
	/*
	 * Reserve some bytes for clone() internal needs
	 * and use as stack the address above this area.
	 */
	return clone(fn, stack_ptr, flags, arg);
}

int clone3_with_pid_noasan(int (*fn)(void *), void *arg, int flags,
			   int exit_signal, pid_t pid)
{
	struct _clone_args c_args = {};

	BUG_ON(flags & CLONE_VM);

	/*
	 * Make sure no child signals are requested. clone3() uses
	 * exit_signal for that.
	 */
	BUG_ON(flags & 0xff);

	pr_debug("Creating process using clone3()\n");

	/*
	 * clone3() explicitly blocks setting an exit_signal
	 * if CLONE_PARENT is specified. With clone() it also
	 * did not work, but there was no error message. The
	 * exit signal from the thread group leader is taken.
	 */
	if (!(flags & CLONE_PARENT)) {
		if (exit_signal != SIGCHLD) {
			pr_err("Exit signal not SIGCHLD\n");
			errno = EINVAL;
			return -1;
		}
		c_args.exit_signal = exit_signal;
	}
	c_args.flags = flags;
	c_args.set_tid = ptr_to_u64(&pid);
	c_args.set_tid_size = 1;
	pid = syscall(__NR_clone3, &c_args, sizeof(c_args));
	if (pid == 0)
		exit(fn(arg));
	return pid;
}
