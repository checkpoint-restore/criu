#include <string.h>
#include <unistd.h>
#include <elf.h>
#include <sys/user.h>
#include <asm/unistd.h>
#include <sys/uio.h>

#include "types.h"
#include <compel/asm/fpu.h>
#include "asm/restorer.h"
#include "asm/dump.h"

#include "cr_options.h"
#include "common/compiler.h"
#include <compel/ptrace.h>
#include "parasite-syscall.h"
#include "log.h"
#include "util.h"
#include "cpu.h"
#include <compel/compel.h>

#include "protobuf.h"
#include "images/core.pb-c.h"
#include "images/creds.pb-c.h"
#include "ptrace.h"
#include "pstree.h"

#define NT_PRFPREG		2
#define NT_S390_VXRS_LOW	0x309
#define NT_S390_VXRS_HIGH	0x30a

/*
 * Print general purpose and access registers
 */
static void print_core_gpregs(const char *msg, UserS390RegsEntry *gpregs)
{
	int i;

	pr_debug("%s: General purpose registers\n", msg);
	pr_debug("       psw %016lx %016lx\n",
		 gpregs->psw_mask, gpregs->psw_addr);
	pr_debug(" orig_gpr2 %016lx\n", gpregs->orig_gpr2);
	for (i = 0; i < 16; i++)
		pr_debug("       g%02d %016lx\n", i, gpregs->gprs[i]);
	for (i = 0; i < 16; i++)
		pr_debug("       a%02d %08x\n", i, gpregs->acrs[i]);
}

/*
 * Print floating point and vector registers
 */
static void print_core_fp_regs(const char *msg, CoreEntry *core)
{
	UserS390VxrsHighEntry *vxrs_high;
	UserS390VxrsLowEntry *vxrs_low;
	UserS390FpregsEntry *fpregs;
	int i;

	vxrs_high = CORE_THREAD_ARCH_INFO(core)->vxrs_high;
	vxrs_low = CORE_THREAD_ARCH_INFO(core)->vxrs_low;
	fpregs = CORE_THREAD_ARCH_INFO(core)->fpregs;

	pr_debug("%s: Floating point registers\n", msg);
	pr_debug("       fpc %08x\n", fpregs->fpc);
	for (i = 0; i < 16; i++)
		pr_debug("       f%02d %016lx\n", i, fpregs->fprs[i]);
	if (!vxrs_low) {
		pr_debug("       No VXRS\n");
		return;
	}
	for (i = 0; i < 16; i++)
		pr_debug("  vx_low%02d %016lx\n", i, vxrs_low->regs[i]);
	for (i = 0; i < 32; i += 2)
		pr_debug(" vx_high%02d %016lx %016lx\n", i / 2,
			 vxrs_high->regs[i], vxrs_high->regs[i + 1]);
}

/*
 * Allocate VxrsLow registers
 */
static UserS390VxrsLowEntry *allocate_vxrs_low_regs(void)
{
	UserS390VxrsLowEntry *vxrs_low;

	vxrs_low = xmalloc(sizeof(*vxrs_low));
	if (!vxrs_low)
		return NULL;
	user_s390_vxrs_low_entry__init(vxrs_low);

	vxrs_low->n_regs = 16;
	vxrs_low->regs = xzalloc(16 * sizeof(uint64_t));
	if (!vxrs_low->regs)
		goto fail_free_vxrs_low;
	return vxrs_low;

fail_free_vxrs_low:
	xfree(vxrs_low);
	return NULL;
}

/*
 * Free VxrsLow registers
 */
static void free_vxrs_low_regs(UserS390VxrsLowEntry *vxrs_low)
{
	if (vxrs_low) {
		xfree(vxrs_low->regs);
		xfree(vxrs_low);
	}
}

/*
 * Allocate VxrsHigh registers
 */
static UserS390VxrsHighEntry *allocate_vxrs_high_regs(void)
{
	UserS390VxrsHighEntry *vxrs_high;

	vxrs_high = xmalloc(sizeof(*vxrs_high));
	if (!vxrs_high)
		return NULL;
	user_s390_vxrs_high_entry__init(vxrs_high);

	vxrs_high->n_regs = 32;
	vxrs_high->regs = xzalloc(32 * sizeof(uint64_t));
	if (!vxrs_high->regs)
		goto fail_free_vxrs_high;
	return vxrs_high;

fail_free_vxrs_high:
	xfree(vxrs_high);
	return NULL;
}

/*
 * Free VxrsHigh registers
 */
static void free_vxrs_high_regs(UserS390VxrsHighEntry *vxrs_high)
{
	if (vxrs_high) {
		xfree(vxrs_high->regs);
		xfree(vxrs_high);
	}
}

/*
 * Copy internal structures into Google Protocol Buffers
 */
int save_task_regs(void *arg, user_regs_struct_t *u, user_fpregs_struct_t *f)
{
	UserS390VxrsHighEntry *vxrs_high;
	UserS390VxrsLowEntry *vxrs_low;
	UserS390FpregsEntry *fpregs;
	UserS390RegsEntry *gpregs;
	CoreEntry *core = arg;

	gpregs = CORE_THREAD_ARCH_INFO(core)->gpregs;
	fpregs = CORE_THREAD_ARCH_INFO(core)->fpregs;

	/* Vector registers */
	if (f->flags & USER_FPREGS_VXRS) {
		vxrs_low = allocate_vxrs_low_regs();
		if (!vxrs_low)
			return -1;
		vxrs_high = allocate_vxrs_high_regs();
		if (!vxrs_high) {
			free_vxrs_low_regs(vxrs_low);
			return -1;
		}
		memcpy(vxrs_low->regs, &f->vxrs_low, sizeof(f->vxrs_low));
		memcpy(vxrs_high->regs, &f->vxrs_high, sizeof(f->vxrs_high));
		CORE_THREAD_ARCH_INFO(core)->vxrs_low = vxrs_low;
		CORE_THREAD_ARCH_INFO(core)->vxrs_high = vxrs_high;
	}
	/* General purpose registers */
	memcpy(gpregs->gprs, u->prstatus.gprs, sizeof(u->prstatus.gprs));
	gpregs->psw_mask = u->prstatus.psw.mask;
	gpregs->psw_addr = u->prstatus.psw.addr;
	/* Access registers */
	memcpy(gpregs->acrs, u->prstatus.acrs, sizeof(u->prstatus.acrs));
	/* System call */
	gpregs->system_call = u->system_call;
	/* Floating point registers */
	fpregs->fpc = f->prfpreg.fpc;
	memcpy(fpregs->fprs, f->prfpreg.fprs, sizeof(f->prfpreg.fprs));
	return 0;
}

/*
 * Copy general and access registers to signal frame
 */
int restore_gpregs(struct rt_sigframe *f, UserS390RegsEntry *src)
{
	_sigregs *dst = &f->uc.uc_mcontext;

	dst->regs.psw.mask = src->psw_mask;
	dst->regs.psw.addr = src->psw_addr;
	memcpy(dst->regs.gprs, src->gprs, sizeof(dst->regs.gprs));
	memcpy(dst->regs.acrs, src->acrs, sizeof(dst->regs.acrs));

	print_core_gpregs("restore_gpregs_regs", src);
	return 0;
}

/*
 * Copy floating point and vector registers to mcontext
 */
int restore_fpu(struct rt_sigframe *f, CoreEntry *core)
{
	UserS390VxrsHighEntry *vxrs_high;
	UserS390VxrsLowEntry *vxrs_low;
	UserS390FpregsEntry *fpregs;
	_sigregs *dst = &f->uc.uc_mcontext;
	_sigregs_ext *dst_ext = &f->uc.uc_mcontext_ext;

	fpregs = CORE_THREAD_ARCH_INFO(core)->fpregs;
	vxrs_high = CORE_THREAD_ARCH_INFO(core)->vxrs_high;
	vxrs_low = CORE_THREAD_ARCH_INFO(core)->vxrs_low;

	dst->fpregs.fpc = fpregs->fpc;
	memcpy(dst->fpregs.fprs, fpregs->fprs, sizeof(dst->fpregs.fprs));
	if (vxrs_low) {
		memcpy(&dst_ext->vxrs_low, vxrs_low->regs,
		       sizeof(dst_ext->vxrs_low));
		memcpy(&dst_ext->vxrs_high, vxrs_high->regs,
		       sizeof(dst_ext->vxrs_high));
	}
	print_core_fp_regs("restore_fp_regs", core);
	return 0;
}

/*
 * Allocate floating point registers
 */
static UserS390FpregsEntry *allocate_fp_regs(void)
{
	UserS390FpregsEntry *fpregs;

	fpregs = xmalloc(sizeof(*fpregs));
	if (!fpregs)
		return NULL;
	user_s390_fpregs_entry__init(fpregs);

	fpregs->n_fprs = 16;
	fpregs->fprs = xzalloc(16 * sizeof(uint64_t));
	if (!fpregs->fprs)
		goto fail_free_fpregs;
	return fpregs;

fail_free_fpregs:
	xfree(fpregs);
	return NULL;
}

/*
 * Free floating point registers
 */
static void free_fp_regs(UserS390FpregsEntry *fpregs)
{
	xfree(fpregs->fprs);
	xfree(fpregs);
}

/*
 * Allocate general purpose and access registers
 */
static UserS390RegsEntry *allocate_gp_regs(void)
{
	UserS390RegsEntry *gpregs;

	gpregs = xmalloc(sizeof(*gpregs));
	if (!gpregs)
		return NULL;
	user_s390_regs_entry__init(gpregs);

	gpregs->n_gprs = 16;
	gpregs->gprs = xzalloc(16 * sizeof(uint64_t));
	if (!gpregs->gprs)
		goto fail_free_gpregs;

	gpregs->n_acrs = 16;
	gpregs->acrs = xzalloc(16 * sizeof(uint32_t));
	if (!gpregs->acrs)
		goto fail_free_gprs;
	return gpregs;

fail_free_gprs:
	xfree(gpregs->gprs);
fail_free_gpregs:
	xfree(gpregs);
	return NULL;
}

/*
 * Free general purpose and access registers
 */
static void free_gp_regs(UserS390RegsEntry *gpregs)
{
	xfree(gpregs->gprs);
	xfree(gpregs->acrs);
	xfree(gpregs);
}

/*
 * Allocate thread info
 */
int arch_alloc_thread_info(CoreEntry *core)
{
	ThreadInfoS390 *ti_s390;

	ti_s390 = xmalloc(sizeof(*ti_s390));
	if (!ti_s390)
		return -1;

	thread_info_s390__init(ti_s390);

	ti_s390->gpregs = allocate_gp_regs();
	if (!ti_s390->gpregs)
		goto fail_free_ti_s390;
	ti_s390->fpregs = allocate_fp_regs();
	if (!ti_s390->fpregs)
		goto fail_free_gp_regs;

	CORE_THREAD_ARCH_INFO(core) = ti_s390;
	return 0;

fail_free_gp_regs:
	free_gp_regs(ti_s390->gpregs);
fail_free_ti_s390:
	xfree(ti_s390);
	return -1;
}

/*
 * Free thread info
 */
void arch_free_thread_info(CoreEntry *core)
{
	if (!CORE_THREAD_ARCH_INFO(core))
		return;
	free_gp_regs(CORE_THREAD_ARCH_INFO(core)->gpregs);
	free_fp_regs(CORE_THREAD_ARCH_INFO(core)->fpregs);
	free_vxrs_low_regs(CORE_THREAD_ARCH_INFO(core)->vxrs_low);
	free_vxrs_high_regs(CORE_THREAD_ARCH_INFO(core)->vxrs_high);
	xfree(CORE_THREAD_ARCH_INFO(core));
	CORE_THREAD_ARCH_INFO(core) = NULL;
}

/*
 * Set regset for pid
 */
static int setregset(int pid, int set, const char *set_str, struct iovec *iov)
{
	if (ptrace(PTRACE_SETREGSET, pid, set, iov) == 0)
		return 0;
	pr_perror("Couldn't set %s registers for pid %d", set_str, pid);
	return -1;
}

/*
 * Set floating point registers for pid from fpregs
 */
static int set_fp_regs(pid_t pid, user_fpregs_struct_t *fpregs)
{
	struct iovec iov;

	iov.iov_base = &fpregs->prfpreg;
	iov.iov_len = sizeof(fpregs->prfpreg);
	return setregset(pid, NT_PRFPREG, "PRFPREG", &iov);
}

/*
 * Set vector registers
 */
static int set_vx_regs(pid_t pid, user_fpregs_struct_t *fpregs)
{
	struct iovec iov;

	if (!(fpregs->flags & USER_FPREGS_VXRS))
		return 0;

	iov.iov_base = &fpregs->vxrs_low;
	iov.iov_len = sizeof(fpregs->vxrs_low);
	if (setregset(pid, NT_S390_VXRS_LOW, "S390_VXRS_LOW", &iov))
		return -1;

	iov.iov_base = &fpregs->vxrs_high;
	iov.iov_len = sizeof(fpregs->vxrs_high);
	return setregset(pid, NT_S390_VXRS_HIGH, "S390_VXRS_HIGH", &iov);
}

/*
 * Restore registers for pid from core
 */
static int set_task_regs(pid_t pid, CoreEntry *core)
{
	UserS390VxrsHighEntry *cvxrs_high;
	UserS390VxrsLowEntry *cvxrs_low;
	UserS390FpregsEntry *cfpregs;
	user_fpregs_struct_t fpregs;

	memset(&fpregs, 0, sizeof(fpregs));
	/* Floating point registers */
	cfpregs = CORE_THREAD_ARCH_INFO(core)->fpregs;
	if (!cfpregs)
		return -1;
	fpregs.prfpreg.fpc = cfpregs->fpc;
	memcpy(fpregs.prfpreg.fprs, cfpregs->fprs, sizeof(fpregs.prfpreg.fprs));
	if (set_fp_regs(pid, &fpregs) < 0)
		return -1;
	/* Vector registers (optional) */
	cvxrs_low = CORE_THREAD_ARCH_INFO(core)->vxrs_low;
	if (!cvxrs_low)
		return 0;
	cvxrs_high = CORE_THREAD_ARCH_INFO(core)->vxrs_high;
	if (!cvxrs_high)
		return -1;
	fpregs.flags |= USER_FPREGS_VXRS;
	memcpy(&fpregs.vxrs_low, cvxrs_low->regs, sizeof(fpregs.vxrs_low));
	memcpy(&fpregs.vxrs_high, cvxrs_high->regs, sizeof(fpregs.vxrs_high));

	return set_vx_regs(pid, &fpregs);
}

/*
 * Restore vector and floating point registers for all threads
 */
int arch_set_thread_regs(struct pstree_item *item)
{
	int i;

	for_each_pstree_item(item) {
		if (item->pid->state == TASK_DEAD ||
		    item->pid->state == TASK_ZOMBIE ||
		    item->pid->state == TASK_HELPER)
			continue;
		for (i = 0; i < item->nr_threads; i++) {
			if (item->threads[i].state == TASK_DEAD ||
			    item->threads[i].state == TASK_ZOMBIE)
				continue;
			if (set_task_regs(item->threads[i].real,
					  item->core[i])) {
				pr_perror("Not set registers for task %d",
					  item->threads[i].real);
				return -1;
			}
		}
	}
	return 0;
}
