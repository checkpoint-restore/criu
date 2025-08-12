#ifndef __CR_ASM_GCS_H__
#define __CR_ASM_GCS_H__

#include <asm/gcs-types.h>

struct rst_shstk_info {
	unsigned long vma_start;      /* start of GCS VMA */
	unsigned long vma_size;	      /* size of GCS VMA */
	unsigned long premapped_addr; /* premapped buffer */
	unsigned long tmp_gcs;	      /* temp area for GCS if needed */
	u64 gcspr_el0;		      /* GCS pointer */
	u64 features_enabled;	      /* GCS flags */
};

#define rst_shstk_info rst_shstk_info

struct task_restore_args;
struct pstree_item;

int arch_gcs_prepare(struct pstree_item *item, CoreEntry *core,
		     struct task_restore_args *ta);
#define arch_shstk_prepare arch_gcs_prepare

int arch_shstk_trampoline(struct pstree_item *item, CoreEntry *core,
			  int (*func)(void *arg), void *arg);
#define arch_shstk_trampoline arch_shstk_trampoline

static always_inline void shstk_set_restorer_stack(struct rst_shstk_info *gcs, void *ptr)
{
	gcs->tmp_gcs = (long unsigned)ptr;
}
#define shstk_set_restorer_stack shstk_set_restorer_stack

static always_inline long shstk_restorer_stack_size(void)
{
	return PAGE_SIZE;
}
#define shstk_restorer_stack_size shstk_restorer_stack_size

#ifdef CR_NOGLIBC
#include <compel/plugins/std/syscall.h>
#include <compel/cpu.h>
#include "vma.h"

static inline unsigned long gcs_map(unsigned long addr, unsigned long size, unsigned int flags)
{
	long gcspr = sys_map_shadow_stack(addr, size, flags);
	pr_info("gcs: syscall: map_shadow_stack at=%lx size=%ld\n", addr, size);

	if (gcspr < 0) {
		pr_err("gcs: failed to map GCS at %lx: %ld\n", addr, gcspr);
		return -1;
	}

	if (addr && gcspr != addr) {
		pr_err("gcs: address mismatch: need %lx, got %lx\n", addr, gcspr);
		return -1;
	}

	pr_info("gcs: mmapped GCS at %lx\n", gcspr);

	return gcspr;
}

/* clang-format off */
static always_inline void gcsss1(unsigned long *Xt)
{
	asm volatile (
		"sys #3, C7, C7, #2, %0\n"
		:
		: "rZ" (Xt)
		: "memory");
}

static always_inline unsigned long *gcsss2(void)
{
	unsigned long *Xt;

	asm volatile (
		"SYSL %0, #3, C7, C7, #3\n"
		: "=r" (Xt)
		:
		: "memory");

	return Xt;
}

static inline void gcsstr(unsigned long addr, unsigned long val)
{
	asm volatile(
		"mov x0, %0\n"
		"mov x1, %1\n"
		".inst 0xd91f1c01\n"  // GCSSTR x1, [x0]
		"mov x0, #0\n"
		:
		: "r"(addr), "r"(val)
		: "x0", "x1", "memory");
}
/* clang-format on */

static always_inline int gcs_restore(struct rst_shstk_info *gcs)
{
	unsigned long gcspr, val;

	if (!(gcs && gcs->features_enabled & PR_SHADOW_STACK_ENABLE)) {
		return 0;
	}

	gcspr = gcs->gcspr_el0 - 8;

	val = ALIGN_DOWN(GCS_SIGNAL_CAP(gcspr), 8);
	pr_debug("gcs: [0] GCSSTR VAL=%lx write at GCSPR=%lx\n", val, gcspr);
	gcsstr(gcspr, val);

	val = ALIGN_DOWN(GCS_SIGNAL_CAP(gcspr), 8) | GCS_CAP_VALID_TOKEN;
	gcspr -= 8;
	pr_debug("gcs: [1] GCSSTR VAL=%lx write at GCSPR=%lx\n", val, gcspr);
	gcsstr(gcspr, val);

	pr_debug("gcs: about to switch stacks via GCSSS1 to: %lx\n", gcspr);
	gcsss1((unsigned long *)gcspr);
	return 0;
}
#define arch_shstk_restore gcs_restore

static always_inline int gcs_vma_restore(VmaEntry *vma_entry)
{
	unsigned long shstk, i, ret;
	unsigned long *gcs_data = (void *)vma_premmaped_start(vma_entry);
	unsigned long vma_size = vma_entry_len(vma_entry);

	shstk = gcs_map(0, vma_size, SHADOW_STACK_SET_TOKEN);
	if (shstk < 0) {
		pr_err("Failed to map shadow stack at %lx: %ld\n", shstk, shstk);
	}

	/* restore shadow stack contents */
	for (i = 0; i < vma_size / 8; i++)
		gcsstr(shstk + i * 8, gcs_data[i]);

	pr_debug("unmap %lx %ld\n", (unsigned long)gcs_data, vma_size);
	ret = sys_munmap(gcs_data, vma_size);
	if (ret < 0) {
		pr_err("Failed to unmap premmaped shadow stack\n");
		return ret;
	}

	vma_premmaped_start(vma_entry) = shstk;

	return 0;
}
#define shstk_vma_restore gcs_vma_restore

static always_inline int gcs_switch_to_restorer(struct rst_shstk_info *gcs)
{
	int ret;
	unsigned long *ssp;
	unsigned long addr;
	unsigned long gcspr;

	if (!(gcs && gcs->features_enabled & PR_SHADOW_STACK_ENABLE)) {
		return 0;
	}

	pr_debug("gcs->premapped_addr + gcs->vma_size = %lx\n", gcs->premapped_addr + gcs->vma_size);
	pr_debug("gcs->tmp_gcs = %lx\n", gcs->tmp_gcs);
	addr = gcs->tmp_gcs;

	if (addr % PAGE_SIZE != 0) {
		pr_err("gcs: 0x%lx not page-aligned to size 0x%lx\n", addr, PAGE_SIZE);
		return -1;
	}

	ret = sys_munmap((void *)addr, PAGE_SIZE);
	if (ret < 0) {
		pr_err("gcs: Failed to unmap aarea for dumpee GCS VMAs\n");
		return -1;
	}

	gcspr = gcs_map(addr, PAGE_SIZE, SHADOW_STACK_SET_TOKEN);

	if (gcspr == -1) {
		pr_err("gcs: failed to gcs_map(%lx, %lx)\n", (unsigned long)addr, PAGE_SIZE);
		return -1;
	}

	ssp = (unsigned long *)(addr + PAGE_SIZE - 8);
	gcsss1(ssp);

	return 0;
}
#define arch_shstk_switch_to_restorer gcs_switch_to_restorer

#endif /* CR_NOGLIBC */

#endif /* __CR_ASM_GCS_H__ */
