#include <sys/ptrace.h>
#include <sys/wait.h>

#include <common/list.h>

#include <compel/cpu.h>

#include "pstree.h"
#include "restorer.h"
#include "rst-malloc.h"
#include "vma.h"

static bool task_needs_shstk(struct pstree_item *item, CoreEntry *core)
{
	UserX86FpregsEntry *fpregs;

	if (!task_alive(item))
		return false;

	fpregs = core->thread_info->fpregs;
	if (fpregs->xsave && fpregs->xsave->cet) {
		if (!compel_cpu_has_feature(X86_FEATURE_SHSTK)) {
			pr_warn_once("Restoring task with shadow stack on non-CET machine\n");
			return false;
		}

		if (fpregs->xsave->cet->cet & ARCH_SHSTK_SHSTK)
			return true;
	}

	return false;
}

static int shstk_prepare_task(struct vm_area_list *vmas,
			      struct rst_shstk_info *shstk)
{
	struct vma_area *vma;

	list_for_each_entry(vma, &vmas->h, list) {
		if (vma_area_is(vma, VMA_AREA_SHSTK) &&
		    in_vma_area(vma, shstk->ssp)) {
			unsigned long premmaped_addr = vma->premmaped_addr;
			unsigned long size = vma_area_len(vma);

			shstk->vma_start = vma->e->start;
			shstk->vma_size = size;
			shstk->premmaped_addr = premmaped_addr;
			shstk->tmp_shstk = premmaped_addr + size;

			break;
		}
	}

	return 0;
}

int arch_shstk_prepare(struct pstree_item *item, CoreEntry *core,
		       struct task_restore_args *ta)
{
	struct thread_restore_args *args_array = (struct thread_restore_args *)(&ta[1]);
	UserX86FpregsEntry *fpregs = core->thread_info->fpregs;
	struct vm_area_list *vmas = &rsti(item)->vmas;
	struct rst_shstk_info *shstk = &ta->shstk;
	int i;

	if (!task_needs_shstk(item, core))
		return 0;

	shstk->cet = fpregs->xsave->cet->cet;
	shstk->ssp = fpregs->xsave->cet->ssp;

	if (shstk_prepare_task(vmas, shstk)) {
		pr_err("Failed to prepare shadow stack memory\n");
		return -1;
	}

	for (i = 0; i < item->nr_threads; i++) {
		struct thread_restore_args *thread_args = &args_array[i];

		core = item->core[i];
		fpregs = core->thread_info->fpregs;
		shstk = &thread_args->shstk;

		shstk->cet = fpregs->xsave->cet->cet;
		shstk->ssp = fpregs->xsave->cet->ssp;
		if (shstk_prepare_task(vmas, shstk)) {
			pr_err("Failed to prepare shadow stack memory\n");
			return -1;
		}
	}

	return 0;
}

int arch_shstk_unlock(struct pstree_item *item, CoreEntry *core, pid_t pid)
{
	unsigned long features;
	int status;
	int ret = -1;

	/*
	 * CRIU runs with no shadow stack and the task does not need one,
	 * nothing to do.
	 */
	if (!kdat.has_shstk && !task_needs_shstk(item, core))
		return 0;

	futex_wait_until(&rsti(item)->shstk_enable, 1);

	if (ptrace(PTRACE_SEIZE, pid, 0, 0)) {
		pr_perror("Cannot attach to %d", pid);
		goto futex_wake;
	}

	if (ptrace(PTRACE_INTERRUPT, pid, 0, 0)) {
		pr_perror("Cannot interrupt the %d task", pid);
		goto detach;
	}

	if (wait4(pid, &status, __WALL, NULL) != pid) {
		pr_perror("waitpid(%d) failed", pid);
		goto detach;
	}

	features = ARCH_SHSTK_SHSTK | ARCH_SHSTK_WRSS;
	if (ptrace(PTRACE_ARCH_PRCTL, pid, features, ARCH_SHSTK_UNLOCK)) {
		pr_perror("Cannot unlock CET for %d task", pid);
		goto detach;
	}

detach:
	if (ptrace(PTRACE_DETACH, pid, NULL, 0)) {
		pr_perror("Unable to detach %d", pid);
		goto futex_wake;
	}

	ret = 0;

futex_wake:
	futex_set_and_wake(&rsti(item)->shstk_unlock, 1);

	return ret;
}

static void shstk_sync_unlock(struct pstree_item *item)
{
	/* notify parent that shadow stack is enabled ... */
	futex_set_and_wake(&rsti(item)->shstk_enable, 1);

	/* ... and wait until it unlocks its features with ptrace */
	futex_wait_until(&rsti(item)->shstk_unlock, 1);
}

static void __arch_shstk_enable(struct pstree_item *item,
				int (*func)(void *arg), void *arg)
{
	int ret;

	shstk_sync_unlock(item);

	/* return here would cause #CP, use exit() instead */
	ret = func(arg);
	exit(ret);
}

static int shstk_disable(struct pstree_item *item)
{
	shstk_sync_unlock(item);

	/* disable shadow stack, implicitly clears ARCH_SHSTK_WRSS */
	if (syscall(__NR_arch_prctl, ARCH_SHSTK_DISABLE, ARCH_SHSTK_SHSTK)) {
		pr_perror("Failed to disable shadow stack");
		return -1;
	}

	if (syscall(__NR_arch_prctl, ARCH_SHSTK_LOCK,
		    ARCH_SHSTK_SHSTK | ARCH_SHSTK_WRSS)) {
		pr_perror("Failed to lock shadow stack controls");
		return -1;
	}

	return 0;
}

int arch_shstk_trampoline(struct pstree_item *item, CoreEntry *core,
		      int (*func)(void *arg), void *arg)
{
	unsigned long features = ARCH_SHSTK_SHSTK;
	int code = ARCH_SHSTK_ENABLE;

	/*
	 * If task does not need shadow stack but CRIU runs with shadow
	 * stack enabled, we should disable it before continuing with
	 * restore
	 */
	if (!task_needs_shstk(item, core)) {
		if (kdat.has_shstk && shstk_disable(item))
			return -1;
		return func(arg);
	}

	/*
	 * Calling sys_arch_prctl() means there will be use of retq
	 * instruction after shadow stack is enabled and this will cause
	 * Control Protectiond fault. Open code sys_arch_prctl() in
	 * assembly.
	 *
	 * code and addr should be in %rdi and %rsi and will be passed to
	 * the system call as is.
	 */
	asm volatile("movq $"__stringify(__NR_arch_prctl)", %%rax	\n"
		     "syscall						\n"
		     "cmpq $0, %%rax					\n"
		     "je 1f						\n"
		     "retq						\n"
		     "1:						\n"
		     :: "D"(code), "S"(features));

	__arch_shstk_enable(item, func, arg);

	/* never reached */
	return -1;
}
