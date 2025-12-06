#ifndef __CR_ASM_SHSTK_H__
#define __CR_ASM_SHSTK_H__

/*
 * Shadow stack constants from Linux
 */
/* arch/x86/include/uapi/asm/mman.h */
#ifndef SHADOW_STACK_SET_TOKEN
#define SHADOW_STACK_SET_TOKEN 0x1     /* Set up a restore token in the shadow stack */
#endif

/* arch/x86/include/uapi/asm/prctl.h */
#define ARCH_SHSTK_ENABLE	0x5001
#define ARCH_SHSTK_DISABLE	0x5002
#define ARCH_SHSTK_LOCK		0x5003
#define ARCH_SHSTK_UNLOCK	0x5004
#define ARCH_SHSTK_STATUS	0x5005

#define ARCH_SHSTK_SHSTK	(1ULL << 0)
#define ARCH_SHSTK_WRSS		(1ULL << 1)

#define ARCH_HAS_SHSTK

/* from arch/x86/kernel/shstk.c */
#define SHSTK_DATA_BIT (1UL << 63)	/* BIT(63) */

/*
 * Shadow stack memory cannot be restored with memcpy/pread but only using
 * a special instruction that can write to shadow stack.
 * That instruction is only available when shadow stack is enabled,
 * otherwise it causes #UD.
 *
 * Also, shadow stack VMAs cannot be mmap()ed or mrepmap()ed, they must be
 * created using map_shadow_stack() system call. This pushes creation of
 * shadow stack VMAs to the restorer blob after CRIU mappings are freed.
 *
 * And there is an additional jungling with shadow stacks to ensure that we
 * don't unmap an active shadow stack
 *
 * The overall sequence of restoring shadow stack is
 * - Enable shadow stack early after clone()ing the task
 * - Unlock shadow stack features using ptrace
 * - In the restorer blob:
 *   - switch to a temporary shadow stack to be able to unmap shadow stack
 *     with the CRIU mappings
 *   - after memory mappigns are restored, recreate shadow stack VMAs,
 *     populate them using wrss instruction and switch to the task shadow
 *     stack
 *   - lock shadow stack features
 */
struct rst_shstk_info {
	unsigned long vma_start;	/* start of shadow stack VMA */
	unsigned long vma_size;		/* size of shadow stack VMA */
	unsigned long premmaped_addr;	/* address of shadow stack copy in
					   the premmaped area */
	unsigned long tmp_shstk;	/* address of temporary shadow stack */
	u64 ssp;			/* shadow stack pointer */
	u64 cet;			/* CET conrtol state */
};
#define rst_shstk_info rst_shstk_info

struct task_restore_args;
struct pstree_item;

int arch_shstk_prepare(struct pstree_item *item, CoreEntry *core,
		       struct task_restore_args *ta);
#define arch_shstk_prepare arch_shstk_prepare

int arch_shstk_unlock(struct pstree_item *item, CoreEntry *core, pid_t pid);
#define arch_shstk_unlock arch_shstk_unlock

int arch_shstk_trampoline(struct pstree_item *item, CoreEntry *core,
		      int (*func)(void *arg), void *arg);
#define arch_shstk_trampoline arch_shstk_trampoline

static always_inline long shstk_restorer_stack_size(void)
{
	return PAGE_SIZE;
}
#define shstk_restorer_stack_size shstk_restorer_stack_size
static always_inline void shstk_set_restorer_stack(struct rst_shstk_info *info, void *ptr)
{
	info->tmp_shstk = (unsigned long)ptr;
}
#define shstk_set_restorer_stack shstk_set_restorer_stack

static always_inline long shstk_min_mmap_addr(struct rst_shstk_info *info, unsigned long __maybe_unused def)
{
	return !(info->cet & ARCH_SHSTK_SHSTK) ? def : (4UL << 30);
}
#define shstk_min_mmap_addr shstk_min_mmap_addr

#ifdef CR_NOGLIBC

#include <compel/plugins/std/syscall.h>
#include <compel/cpu.h>
#include "vma.h"

#define SHSTK_BUSY_BIT (1UL << 0)	/* BIT(0) */

static inline int shstk_map(unsigned long addr, unsigned long size)
{
	long shstk = sys_map_shadow_stack(addr, size, SHADOW_STACK_SET_TOKEN);

	if (shstk < 0) {
		pr_err("Failed to map shadow stack at %lx: %ld\n", addr, shstk);
		return -1;
	}

	if (shstk != addr) {
		pr_err("Shadow stack address mismatch: need %lx, got %lx\n", addr, shstk);
		return -1;
	}

	pr_info("Created shadow stack at %lx\n", shstk);

	return 0;
}

/* clang-format off */
static inline unsigned long get_ssp(void)
{
	unsigned long ssp;

	asm volatile("rdsspq %0" : "=r"(ssp) :: );

	return ssp;
}

static inline void wrssq(unsigned long addr, unsigned long val)
{
	asm volatile("wrssq %1, (%0)" :: "r"(addr), "r"(val) : "memory");
}
/* clang-format off */

static always_inline void shstk_switch_ssp(unsigned long new_ssp)
{
	unsigned long old_ssp = get_ssp();

	asm volatile("rstorssp (%0)\n" :: "r"(new_ssp));
	asm volatile("saveprevssp");

	pr_debug("changed ssp from %lx to %lx\n", old_ssp, new_ssp);
}

/*
 * Disable writes to the shadow stack and lock it's disable/enable control
 */
static inline int shstk_finalize(void)
{
	int ret = 0;

	ret = sys_arch_prctl(ARCH_SHSTK_DISABLE, ARCH_SHSTK_WRSS);
	if (ret) {
		pr_err("Failed to disable writes to shadow stack\n");
		return ret;
	}

	ret = sys_arch_prctl(ARCH_SHSTK_LOCK, ARCH_SHSTK_SHSTK);
	if (ret)
		pr_err("Failed to lock shadow stack controls\n");

	return ret;
}

/*
 * Create shadow stack vma and restore its content from premmapped anonymous (non-shstk) vma
 */
static always_inline int shstk_vma_restore(VmaEntry *vma_entry)
{
	long shstk, i;
	unsigned long *shstk_data = (void *)vma_premmaped_start(vma_entry);
	unsigned long vma_size = vma_entry_len(vma_entry);
	long ret;

	shstk = sys_map_shadow_stack(0, vma_size, SHADOW_STACK_SET_TOKEN);
	if (shstk < 0) {
		pr_err("Failed to map shadow stack: %ld\n", shstk);
		return -1;
	}

	/* restore shadow stack contents */
	for (i = 0; i < vma_size / 8; i++)
		wrssq(shstk + i * 8, shstk_data[i]);

	ret = sys_munmap(shstk_data, vma_size);
	if (ret < 0) {
		pr_err("Failed to unmap premmaped shadow stack\n");
		return ret;
	}

	/*
	 * From that point premapped vma is (shstk) and we need
	 * to mremap() it to the final location. Originally premapped
	 * (shstk_data) has been unmapped already.
	 */
	vma_premmaped_start(vma_entry) = shstk;

	return 0;
}
#define shstk_vma_restore shstk_vma_restore

/*
 * Restore contents of the shadow stack and set shadow stack pointer
 */
static always_inline int shstk_restore(struct rst_shstk_info *cet)
{
	unsigned long ssp, val;

	if (!(cet->cet & ARCH_SHSTK_SHSTK))
		return 0;

	/*
	 * Add tokens for sigreturn frame and for switch of the shadow stack.
	 * The sigreturn token will be checked by the kernel during
	 * processing of sigreturn
	 * The token for stack switch is required by rstorssp and
	 * saveprevssp semantics
	 */

	/* token for sigreturn frame */
	ssp = cet->ssp - 8;
	val = ALIGN_DOWN(cet->ssp, 8) | SHSTK_DATA_BIT;
	wrssq(ssp, val);

	/* shadow stack switch token */
	val = ssp | SHSTK_BUSY_BIT;
	ssp -= 8;
	wrssq(ssp, val);

	/* reset shadow stack pointer to the proper location */
	shstk_switch_ssp(ssp);

	return shstk_finalize();
}
#define arch_shstk_restore shstk_restore

/*
 * Disable shadow stack
 */
static inline int shstk_disable(void)
{
	int ret;

	ret = sys_arch_prctl(ARCH_SHSTK_DISABLE, ARCH_SHSTK_WRSS);
	if (ret) {
		pr_err("Failed to disable writes to shadow stack\n");
		return ret;
	}

	ret = sys_arch_prctl(ARCH_SHSTK_DISABLE, ARCH_SHSTK_SHSTK);
	if (ret) {
		pr_err("Failed to disable shadow stack\n");
		return ret;
	}

	ret = sys_arch_prctl(ARCH_SHSTK_LOCK, ARCH_SHSTK_SHSTK);
	if (ret)
		pr_err("Failed to lock shadow stack controls\n");

	return 0;
}

/*
 * Switch to temporary shadow stack
 */
static always_inline int shstk_switch_to_restorer(struct rst_shstk_info *cet)
{
	unsigned long ssp;
	long ret;

	if (!(cet->cet & ARCH_SHSTK_SHSTK))
		return 0;

	ret = sys_munmap((void *)cet->tmp_shstk, PAGE_SIZE);
	if (ret < 0) {
		pr_err("Failed to unmap area for temporary shadow stack\n");
		return -1;
	}

	ret = shstk_map(cet->tmp_shstk, PAGE_SIZE);
	if (ret < 0)
		return -1;

	/*
	 * Switch shadow stack from the default created by the kernel to a
	 * temporary shadow stack allocated in the premmaped area
	 */
	ssp = cet->tmp_shstk + PAGE_SIZE - 8;
	shstk_switch_ssp(ssp);

	ret = sys_arch_prctl(ARCH_SHSTK_ENABLE, ARCH_SHSTK_WRSS);
	if (ret) {
		pr_err("Failed to enable writes to shadow stack\n");
		return ret;
	}

	return 0;
}
#define arch_shstk_switch_to_restorer shstk_switch_to_restorer

#endif /* CR_NOGLIBC */

#endif /* __CR_ASM_SHSTK_H__ */
