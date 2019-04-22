#include <sched.h>
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
