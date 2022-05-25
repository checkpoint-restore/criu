#ifndef __CR_ASM_SHSTK_H__
#define __CR_ASM_SHSTK_H__

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

#endif /* __CR_ASM_SHSTK_H__ */
