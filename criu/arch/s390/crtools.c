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
#include "compel/infect.h"

#include "protobuf.h"
#include "images/core.pb-c.h"
#include "images/creds.pb-c.h"
#include "ptrace.h"
#include "pstree.h"
#include "image.h"

#define NT_PRFPREG	  2
#define NT_S390_VXRS_LOW  0x309
#define NT_S390_VXRS_HIGH 0x30a
#define NT_S390_GS_CB	  0x30b
#define NT_S390_GS_BC	  0x30c
#define NT_S390_RI_CB	  0x30d

/*
 * Print general purpose and access registers
 */
static void print_core_gpregs(const char *msg, UserS390RegsEntry *gpregs)
{
	int i;

	pr_debug("%s: General purpose registers\n", msg);
	pr_debug("       psw %016lx %016lx\n", gpregs->psw_mask, gpregs->psw_addr);
	pr_debug(" orig_gpr2 %016lx\n", gpregs->orig_gpr2);
	for (i = 0; i < 16; i++)
		pr_debug("       g%02d %016lx\n", i, gpregs->gprs[i]);
	for (i = 0; i < 16; i++)
		pr_debug("       a%02d %08x\n", i, gpregs->acrs[i]);
}

/*
 * Print vector registers
 */
static void print_core_vx_regs(CoreEntry *core)
{
	UserS390VxrsHighEntry *vxrs_high;
	UserS390VxrsLowEntry *vxrs_low;
	int i;

	vxrs_high = CORE_THREAD_ARCH_INFO(core)->vxrs_high;
	vxrs_low = CORE_THREAD_ARCH_INFO(core)->vxrs_low;

	if (vxrs_low == NULL) {
		pr_debug("       No VXRS\n");
		return;
	}
	for (i = 0; i < 16; i++)
		pr_debug("  vx_low%02d %016lx\n", i, vxrs_low->regs[i]);
	for (i = 0; i < 32; i += 2)
		pr_debug(" vx_high%02d %016lx %016lx\n", i / 2, vxrs_high->regs[i], vxrs_high->regs[i + 1]);
}

/*
 * Print guarded-storage control block
 */
static void print_core_gs_cb(CoreEntry *core)
{
	UserS390GsCbEntry *gs_cb;
	int i;

	gs_cb = CORE_THREAD_ARCH_INFO(core)->gs_cb;
	if (!gs_cb) {
		pr_debug("       No GS_CB\n");
		return;
	}
	for (i = 0; i < 4; i++)
		pr_debug("       gs_cb%d %lx\n", i, gs_cb->regs[i]);
}

/*
 * Print guarded-storage broadcast control block
 */
static void print_core_gs_bc(CoreEntry *core)
{
	UserS390GsCbEntry *gs_bc;
	int i;

	gs_bc = CORE_THREAD_ARCH_INFO(core)->gs_bc;

	if (!gs_bc) {
		pr_debug("       No GS_BC\n");
		return;
	}
	for (i = 0; i < 4; i++)
		pr_debug("       gs_bc%d %lx\n", i, gs_bc->regs[i]);
}

/*
 * Print runtime-instrumentation control block
 */
static void print_core_ri_cb(CoreEntry *core)
{
	UserS390RiEntry *ri_cb;
	int i;

	ri_cb = CORE_THREAD_ARCH_INFO(core)->ri_cb;
	if (!ri_cb) {
		pr_debug("       No RI_CB\n");
		return;
	}
	for (i = 0; i < 8; i++)
		pr_debug("       ri_cb%d %lx\n", i, ri_cb->regs[i]);
}
/*
 * Print architecture registers
 */
static void print_core_fp_regs(const char *msg, CoreEntry *core)
{
	UserS390FpregsEntry *fpregs;
	int i;

	fpregs = CORE_THREAD_ARCH_INFO(core)->fpregs;

	pr_debug("%s: Floating point registers\n", msg);
	pr_debug("       fpc %08x\n", fpregs->fpc);
	for (i = 0; i < 16; i++)
		pr_debug("       f%02d %016lx\n", i, fpregs->fprs[i]);
	print_core_vx_regs(core);
	print_core_gs_cb(core);
	print_core_gs_bc(core);
	print_core_ri_cb(core);
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
 * Allocate guarded-storage control block (GS_CB and GS_BC)
 */
static UserS390GsCbEntry *allocate_gs_cb(void)
{
	UserS390GsCbEntry *gs_cb;

	gs_cb = xmalloc(sizeof(*gs_cb));
	if (!gs_cb)
		return NULL;
	user_s390_gs_cb_entry__init(gs_cb);

	gs_cb->n_regs = 4;
	gs_cb->regs = xzalloc(4 * sizeof(uint64_t));
	if (!gs_cb->regs)
		goto fail_free_gs_cb;
	return gs_cb;

fail_free_gs_cb:
	xfree(gs_cb);
	return NULL;
}

/*
 * Free Guarded Storage control blocks
 */
static void free_gs_cb(UserS390GsCbEntry *gs_cb)
{
	if (gs_cb) {
		xfree(gs_cb->regs);
		xfree(gs_cb);
	}
}

/*
 * Allocate runtime-instrumentation control block
 */
static UserS390RiEntry *allocate_ri_cb(void)
{
	UserS390RiEntry *ri_cb;

	ri_cb = xmalloc(sizeof(*ri_cb));
	if (!ri_cb)
		return NULL;
	user_s390_ri_entry__init(ri_cb);

	ri_cb->ri_on = 0;
	ri_cb->n_regs = 8;
	ri_cb->regs = xzalloc(8 * sizeof(uint64_t));
	if (!ri_cb->regs)
		goto fail_free_ri_cb;
	return ri_cb;

fail_free_ri_cb:
	xfree(ri_cb);
	return NULL;
}

/*
 * Free runtime-instrumentation control block
 */
static void free_ri_cb(UserS390RiEntry *ri_cb)
{
	if (ri_cb) {
		xfree(ri_cb->regs);
		xfree(ri_cb);
	}
}

/*
 * Copy internal structures into Google Protocol Buffers
 */
int save_task_regs(pid_t pid, void *arg, user_regs_struct_t *u, user_fpregs_struct_t *f)
{
	UserS390VxrsHighEntry *vxrs_high = NULL;
	UserS390VxrsLowEntry *vxrs_low = NULL;
	UserS390FpregsEntry *fpregs = NULL;
	UserS390RegsEntry *gpregs = NULL;
	UserS390GsCbEntry *gs_cb = NULL;
	UserS390GsCbEntry *gs_bc = NULL;
	UserS390RiEntry *ri_cb = NULL;
	CoreEntry *core = arg;

	gpregs = CORE_THREAD_ARCH_INFO(core)->gpregs;
	fpregs = CORE_THREAD_ARCH_INFO(core)->fpregs;

	/* Vector registers */
	if (f->flags & USER_FPREGS_VXRS) {
		vxrs_low = allocate_vxrs_low_regs();
		if (!vxrs_low)
			return -1;
		vxrs_high = allocate_vxrs_high_regs();
		if (!vxrs_high)
			goto fail_free_vxrs_low;
		memcpy(vxrs_low->regs, &f->vxrs_low, sizeof(f->vxrs_low));
		memcpy(vxrs_high->regs, &f->vxrs_high, sizeof(f->vxrs_high));
		CORE_THREAD_ARCH_INFO(core)->vxrs_low = vxrs_low;
		CORE_THREAD_ARCH_INFO(core)->vxrs_high = vxrs_high;
	}
	/* Guarded-storage control block */
	if (f->flags & USER_GS_CB) {
		gs_cb = allocate_gs_cb();
		if (!gs_cb)
			goto fail_free_gs_cb;
		memcpy(gs_cb->regs, &f->gs_cb, sizeof(f->gs_cb));
		CORE_THREAD_ARCH_INFO(core)->gs_cb = gs_cb;
	}
	/* Guarded-storage broadcast control block */
	if (f->flags & USER_GS_BC) {
		gs_bc = allocate_gs_cb();
		if (!gs_bc)
			goto fail_free_gs_bc;
		memcpy(gs_bc->regs, &f->gs_bc, sizeof(f->gs_bc));
		CORE_THREAD_ARCH_INFO(core)->gs_bc = gs_bc;
	}
	/* Runtime-instrumentation control block */
	if (f->flags & USER_RI_CB) {
		ri_cb = allocate_ri_cb();
		if (!ri_cb)
			goto fail_free_ri_cb;
		memcpy(ri_cb->regs, &f->ri_cb, sizeof(f->ri_cb));
		CORE_THREAD_ARCH_INFO(core)->ri_cb = ri_cb;
		/* We need to remember that the RI bit was on */
		if (f->flags & USER_RI_ON)
			ri_cb->ri_on = 1;
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
fail_free_ri_cb:
	free_ri_cb(ri_cb);
fail_free_gs_cb:
	free_gs_cb(gs_cb);
fail_free_gs_bc:
	free_gs_cb(gs_bc);
fail_free_vxrs_low:
	free_vxrs_low_regs(vxrs_low);
	return -1;
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
		memcpy(&dst_ext->vxrs_low, vxrs_low->regs, sizeof(dst_ext->vxrs_low));
		memcpy(&dst_ext->vxrs_high, vxrs_high->regs, sizeof(dst_ext->vxrs_high));
	}
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
	free_gs_cb(CORE_THREAD_ARCH_INFO(core)->gs_cb);
	free_gs_cb(CORE_THREAD_ARCH_INFO(core)->gs_bc);
	free_ri_cb(CORE_THREAD_ARCH_INFO(core)->ri_cb);
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
 * Set guarded-storage control block
 */
static int set_gs_cb(pid_t pid, user_fpregs_struct_t *fpregs)
{
	struct iovec iov;

	if (fpregs->flags & USER_GS_CB) {
		iov.iov_base = &fpregs->gs_cb;
		iov.iov_len = sizeof(fpregs->gs_cb);
		if (setregset(pid, NT_S390_GS_CB, "S390_GS_CB", &iov))
			return -1;
	}

	if (!(fpregs->flags & USER_GS_BC))
		return 0;
	iov.iov_base = &fpregs->gs_bc;
	iov.iov_len = sizeof(fpregs->gs_bc);
	return setregset(pid, NT_S390_GS_BC, "S390_GS_BC", &iov);
}

/*
 * Set runtime-instrumentation control block
 */
static int set_ri_cb(pid_t pid, user_fpregs_struct_t *fpregs)
{
	struct iovec iov;

	if (!(fpregs->flags & USER_RI_CB))
		return 0;

	iov.iov_base = &fpregs->ri_cb;
	iov.iov_len = sizeof(fpregs->ri_cb);
	return setregset(pid, NT_S390_RI_CB, "S390_RI_CB", &iov);
}

/*
 * Set runtime-instrumentation bit
 *
 * The CPU collects information when the RI bit of the PSW is set.
 * The RI control block is not part of the signal frame. Therefore during
 * sigreturn it is not set. If the RI control block is present, the CPU
 * writes into undefined storage. Hence, we have disabled the RI bit in
 * the sigreturn PSW and set this bit after sigreturn by modifying the PSW
 * of the task.
 */
static int set_ri_bit(pid_t pid)
{
	user_regs_struct_t regs;
	struct iovec iov;
	psw_t *psw;

	iov.iov_base = &regs.prstatus;
	iov.iov_len = sizeof(regs.prstatus);
	if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
		pr_perror("Fail to activate RI bit");
		return -1;
	}
	psw = &regs.prstatus.psw;
	psw->mask |= PSW_MASK_RI;

	return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}

/*
 * Restore registers not present in sigreturn signal frame
 */
static int set_task_regs_nosigrt(pid_t pid, CoreEntry *core)
{
	user_fpregs_struct_t fpregs;
	UserS390GsCbEntry *cgs_cb;
	UserS390GsCbEntry *cgs_bc;
	UserS390RiEntry *cri_cb;
	int ret = 0;

	memset(&fpregs, 0, sizeof(fpregs));
	/* Guarded-storage control block (optional) */
	cgs_cb = CORE_THREAD_ARCH_INFO(core)->gs_cb;
	if (cgs_cb != NULL) {
		fpregs.flags |= USER_GS_CB;
		memcpy(&fpregs.gs_cb, cgs_cb->regs, sizeof(fpregs.gs_cb));
	}
	/* Guarded-storage broadcast control block (optional) */
	cgs_bc = CORE_THREAD_ARCH_INFO(core)->gs_bc;
	if (cgs_bc != NULL) {
		fpregs.flags |= USER_GS_BC;
		memcpy(&fpregs.gs_bc, cgs_bc->regs, sizeof(fpregs.gs_bc));
	}
	if (set_gs_cb(pid, &fpregs) < 0)
		return -1;
	/* Runtime-instrumentation control block (optional) */
	cri_cb = CORE_THREAD_ARCH_INFO(core)->ri_cb;
	if (cri_cb != NULL) {
		fpregs.flags |= USER_RI_CB;
		memcpy(&fpregs.ri_cb, cri_cb->regs, sizeof(fpregs.ri_cb));
		if (set_ri_cb(pid, &fpregs) < 0)
			return -1;
		if (cri_cb->ri_on) {
			fpregs.flags |= USER_RI_ON;
			ret = set_ri_bit(pid);
		}
	}
	return ret;
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
	if (cvxrs_low != NULL) {
		cvxrs_high = CORE_THREAD_ARCH_INFO(core)->vxrs_high;
		if (!cvxrs_high)
			return -1;
		fpregs.flags |= USER_FPREGS_VXRS;
		memcpy(&fpregs.vxrs_low, cvxrs_low->regs, sizeof(fpregs.vxrs_low));
		memcpy(&fpregs.vxrs_high, cvxrs_high->regs, sizeof(fpregs.vxrs_high));
		if (set_vx_regs(pid, &fpregs) < 0)
			return -1;
	}
	return set_task_regs_nosigrt(pid, core);
}

/*
 * Restore registers for all threads:
 * - Floating point registers
 * - Vector registers
 * - Guarded-storage control block
 * - Guarded-storage broadcast control block
 * - Runtime-instrumentation control block
 */
int arch_set_thread_regs(struct pstree_item *item, bool with_threads)
{
	int i;

	for_each_pstree_item(item) {
		if (item->pid->state == TASK_DEAD || item->pid->state == TASK_ZOMBIE)
			continue;
		for (i = 0; i < item->nr_threads; i++) {
			if (item->threads[i].state == TASK_DEAD || item->threads[i].state == TASK_ZOMBIE)
				continue;
			if (!with_threads && i > 0)
				continue;
			if (set_task_regs(item->threads[i].real, item->core[i])) {
				pr_perror("Not set registers for task %d", item->threads[i].real);
				return -1;
			}
		}
	}
	return 0;
}

static int open_core(int pid, CoreEntry **pcore)
{
	struct cr_img *img;
	int ret;

	img = open_image(CR_FD_CORE, O_RSTR, pid);
	if (!img) {
		pr_err("Can't open core data for %d\n", pid);
		return -1;
	}
	ret = pb_read_one(img, pcore, PB_CORE);
	close_image(img);

	return ret <= 0 ? -1 : 0;
}

/*
 * Restore all registers not present in sigreturn signal frame
 *
 * - Guarded-storage control block
 * - Guarded-storage broadcast control block
 * - Runtime-instrumentation control block
 */
int arch_set_thread_regs_nosigrt(struct pid *pid)
{
	CoreEntry *core;

	core = xmalloc(sizeof(*core));
	if (open_core(pid->ns[0].virt, &core) < 0) {
		pr_perror("Cannot open core for virt pid %d", pid->ns[0].virt);
		return -1;
	}

	if (set_task_regs_nosigrt(pid->real, core) < 0) {
		pr_perror("Set register for pid %d", pid->real);
		return -1;
	}
	print_core_fp_regs("restore_fp_regs", core);
	return 0;
}
