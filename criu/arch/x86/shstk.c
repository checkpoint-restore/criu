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
