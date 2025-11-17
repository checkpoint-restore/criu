#include <sys/ptrace.h>
#include <sys/wait.h>

#include <common/list.h>
#include <compel/cpu.h>

#include "asm/gcs-types.h"
#include "pstree.h"
#include "restorer.h"
#include "rst-malloc.h"
#include "vma.h"

#include <sys/auxv.h>
#include <stdbool.h>

static bool task_has_gcs_enabled(UserAarch64GcsEntry *gcs)
{
	return gcs && (gcs->features_enabled & PR_SHADOW_STACK_ENABLE) != 0;
}

static bool host_supports_gcs(void)
{
	unsigned long hwcap = getauxval(AT_HWCAP);
	return (hwcap & HWCAP_GCS) != 0;
}

static bool task_needs_gcs(struct pstree_item *item, CoreEntry *core)
{
	UserAarch64GcsEntry *gcs;

	if (!task_alive(item))
		return false;

	gcs = core->ti_aarch64->gcs;

	if (task_has_gcs_enabled(gcs)) {
		if (!host_supports_gcs()) {
			pr_warn_once("Restoring task with GCS on non-GCS host\n");
			return false;
		}

		pr_info("Restoring task with GCS\n");
		return true;
	}

	pr_info("Restoring a task without GCS\n");
	return false;
}

static int gcs_prepare_task(struct vm_area_list *vmas,
			    struct rst_shstk_info *gcs)
{
	struct vma_area *vma;

	list_for_each_entry(vma, &vmas->h, list) {
		if (vma_area_is(vma, VMA_AREA_SHSTK) &&
		    in_vma_area(vma, gcs->gcspr_el0)) {
			unsigned long premapped_addr = vma->premmaped_addr;
			unsigned long size = vma_area_len(vma);

			gcs->vma_start = vma->e->start;
			gcs->vma_size = size;
			gcs->premapped_addr = premapped_addr;

			return 0;
		}
	}

	pr_err("Unable to find a shadow stack vma: %lx\n", gcs->gcspr_el0);
	return -1;
}

int arch_gcs_prepare(struct pstree_item *item, CoreEntry *core,
		     struct task_restore_args *ta)
{
	int i;
	struct thread_restore_args *args_array = (struct thread_restore_args *)(&ta[1]);
	struct vm_area_list *vmas = &rsti(item)->vmas;
	struct rst_shstk_info *gcs = &ta->shstk;

	if (!task_needs_gcs(item, core))
		return 0;

	gcs->gcspr_el0 = core->ti_aarch64->gcs->gcspr_el0;
	gcs->features_enabled = core->ti_aarch64->gcs->features_enabled;

	if (gcs_prepare_task(vmas, gcs)) {
		pr_err("gcs: failed to prepare shadow stack memory\n");
		return -1;
	}

	for (i = 0; i < item->nr_threads; i++) {
		struct thread_restore_args *thread_args = &args_array[i];

		core = item->core[i];
		gcs = &thread_args->shstk;

		gcs->gcspr_el0 = core->ti_aarch64->gcs->gcspr_el0;
		gcs->features_enabled = core->ti_aarch64->gcs->features_enabled;

		if (gcs_prepare_task(vmas, gcs)) {
			pr_err("gcs: failed to prepare GCS memory\n");
			return -1;
		}
	}

	return 0;
}

int arch_shstk_trampoline(struct pstree_item *item, CoreEntry *core,
			  int (*func)(void *arg), void *arg)
{
	int fret;
	unsigned long flags = PR_SHADOW_STACK_ENABLE |
			      PR_SHADOW_STACK_PUSH |
			      PR_SHADOW_STACK_WRITE;

	long ret, x1_after, x8_after;

	/* If task doesn't need GCS, just call func */
	if (!task_needs_gcs(item, core)) {
		return func(arg);
	}

	pr_debug("gcs: GCS enable SVC about to fire: x8=%d x0=%d x1=0x%lx\n",
		 __NR_prctl, PR_SET_SHADOW_STACK_STATUS, flags);

	asm volatile(
		"mov x0, %3\n"	// x0 = PR_SET_SHADOW_STACK_STATUS (75)
		"mov x1, %4\n"	// x1 = flags
		"mov x2, xzr\n" // x2 = 0
		"mov x3, xzr\n" // x3 = 0
		"mov x4, xzr\n" // x4 = 0
		"mov x8, %5\n"	// x8 = __NR_prctl (167)
		"svc #0\n"	// Invoke syscall
		"mov %0, x0\n"	// Capture return value
		"mov %1, x1\n"	// Capture x1 after
		"mov %2, x8\n"	// Capture x8 after
		: "=r"(ret), "=r"(x1_after), "=r"(x8_after)
		: "i"(PR_SET_SHADOW_STACK_STATUS), // x0 - %3rd
		  "r"(flags),			   // x1 - %4th
		  "i"(__NR_prctl)		   // x8 - %5th
		: "x0", "x1", "x2", "x3", "x4", "x8", "memory", "cc");

	pr_info("gcs: after SVC: ret=%ld x1=%ld x8=%ld\n", ret, x1_after, x8_after);

	if (ret != 0) {
		int err = errno;
		pr_err("gcs: failed to enable GCS: ret=%ld errno=%d (%s)\n", ret, err, strerror(err));
		return -1;
	}

	fret = func(arg);
	exit(fret);

	return -1;
}
