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
#define ARCH_SHSTK_ENABLE		0x5001
#define ARCH_SHSTK_DISABLE	0x5002
#define ARCH_SHSTK_LOCK		0x5003
#define ARCH_SHSTK_UNLOCK		0x5004
#define ARCH_SHSTK_STATUS		0x5005

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

#if 0
int arch_shstk_unlock(struct pstree_item *item, CoreEntry *core, pid_t pid);
#define arch_shstk_unlock arch_shstk_unlock

int arch_shstk_trampoline(struct pstree_item *item, CoreEntry *core,
		      int (*func)(void *arg), void *arg);
#define arch_shstk_trampoline arch_shstk_trampoline
#endif

#endif /* __CR_ASM_SHSTK_H__ */
