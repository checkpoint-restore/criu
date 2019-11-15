#include <sched.h>
#include <sys/mman.h>
#include "common/compiler.h"
#include "clone-noasan.h"
#include "log.h"
#include "common/bug.h"

#undef LOG_PREFIX
#define LOG_PREFIX "clone_noasan: "

static struct {
	mutex_t		op_mutex;
	mutex_t		*clone_mutex;
} *context;

int clone_noasan_init(void)
{
	context = mmap(NULL, sizeof(*context), PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (context == MAP_FAILED) {
		pr_perror("Can't allocate context");
		return -1;
	}

	mutex_init(&context->op_mutex);
	return 0;
}

void clone_noasan_fini(void)
{
	munmap(context, sizeof(*context));
	context = NULL;
}

static inline void context_lock(void)
{
	if (context && context->clone_mutex)
		mutex_lock(context->clone_mutex);
}

static inline void context_unlock(void)
{
	if (context && context->clone_mutex)
		mutex_unlock(context->clone_mutex);
}

int clone_noasan_set_mutex(mutex_t *clone_mutex)
{
	if (!context) {
		pr_err_once("Context is missing\n");
		return -ENOENT;
	}

	mutex_lock(&context->op_mutex);
	if (context->clone_mutex)
		return -EBUSY;
	context->clone_mutex = clone_mutex;
	mutex_unlock(&context->op_mutex);

	return 0;
}

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
	int ret;
	/*
	 * Reserve some bytes for clone() internal needs
	 * and use as stack the address above this area.
	 */
	context_lock();
	ret = clone(fn, stack_ptr, flags, arg);
	context_unlock();
	return ret;
}
