#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <compel/plugins/std/syscall-codes.h>
#include "uapi/compel/asm/infect-types.h"
#include "errno.h"
#include "log.h"
#include "common/bug.h"
#include "infect.h"
#include "ptrace.h"
#include "infect-priv.h"

#define NT_PRFPREG	  2
#define NT_S390_VXRS_LOW  0x309
#define NT_S390_VXRS_HIGH 0x30a
#define NT_S390_GS_CB	  0x30b
#define NT_S390_GS_BC	  0x30c
#define NT_S390_RI_CB	  0x30d

/*
 * Print general purpose and access registers
 */
static void print_user_regs_struct(const char *msg, int pid, user_regs_struct_t *regs)
{
	int i;

	pr_debug("%s: Registers for pid=%d\n", msg, pid);
	pr_debug("system_call %08lx\n", (unsigned long)regs->system_call);
	pr_debug("       psw %016lx %016lx\n", regs->prstatus.psw.mask, regs->prstatus.psw.addr);
	pr_debug(" orig_gpr2 %016lx\n", regs->prstatus.orig_gpr2);
	for (i = 0; i < 16; i++)
		pr_debug("       g%02d %016lx\n", i, regs->prstatus.gprs[i]);
	for (i = 0; i < 16; i++)
		pr_debug("       a%02d %08x\n", i, regs->prstatus.acrs[i]);
}

/*
 * Print vector registers
 */
static void print_vxrs(user_fpregs_struct_t *fpregs)
{
	int i;

	if (!(fpregs->flags & USER_FPREGS_VXRS)) {
		pr_debug("       No VXRS\n");
		return;
	}
	for (i = 0; i < 16; i++)
		pr_debug("  vx_low%02d %016lx\n", i, fpregs->vxrs_low[i]);
	for (i = 0; i < 16; i++)
		pr_debug(" vx_high%02d %016lx %016lx\n", i, fpregs->vxrs_high[i].part1, fpregs->vxrs_high[i].part2);
}

/*
 * Print guarded-storage control block
 */
static void print_gs_cb(user_fpregs_struct_t *fpregs)
{
	int i;

	if (!(fpregs->flags & USER_GS_CB)) {
		pr_debug("       No GS_CB\n");
		return;
	}
	for (i = 0; i < 4; i++)
		pr_debug("  gs_cb%02d %016lx\n", i, fpregs->gs_cb[i]);
}

/*
 * Print guarded-storage broadcast control block
 */
static void print_gs_bc(user_fpregs_struct_t *fpregs)
{
	int i;

	if (!(fpregs->flags & USER_GS_BC)) {
		pr_debug("       No GS_BC\n");
		return;
	}
	for (i = 0; i < 4; i++)
		pr_debug("  gs_bc%02d %016lx\n", i, fpregs->gs_bc[i]);
}

/*
 * Print runtime-instrumentation control block
 */
static void print_ri_cb(user_fpregs_struct_t *fpregs)
{
	int i;

	if (!(fpregs->flags & USER_RI_CB)) {
		pr_debug("       No RI_CB\n");
		return;
	}
	for (i = 0; i < 8; i++)
		pr_debug("  ri_cb%02d %016lx\n", i, fpregs->ri_cb[i]);
}

/*
 * Print FP registers, VX registers, guarded-storage, and
 * runtime-instrumentation
 */
static void print_user_fpregs_struct(const char *msg, int pid, user_fpregs_struct_t *fpregs)
{
	int i;

	pr_debug("%s: FP registers for pid=%d\n", msg, pid);
	pr_debug("       fpc %08x\n", fpregs->prfpreg.fpc);
	for (i = 0; i < 16; i++)
		pr_debug("       f%02d %016lx\n", i, fpregs->prfpreg.fprs[i]);
	print_vxrs(fpregs);
	print_gs_cb(fpregs);
	print_gs_bc(fpregs);
	print_ri_cb(fpregs);
}

int sigreturn_prep_regs_plain(struct rt_sigframe *sigframe, user_regs_struct_t *regs, user_fpregs_struct_t *fpregs)
{
	_sigregs_ext *dst_ext = &sigframe->uc.uc_mcontext_ext;
	_sigregs *dst = &sigframe->uc.uc_mcontext;

	memcpy(dst->regs.gprs, regs->prstatus.gprs, sizeof(regs->prstatus.gprs));
	memcpy(dst->regs.acrs, regs->prstatus.acrs, sizeof(regs->prstatus.acrs));
	memcpy(&dst->regs.psw, &regs->prstatus.psw, sizeof(regs->prstatus.psw));
	memcpy(&dst->fpregs.fpc, &fpregs->prfpreg.fpc, sizeof(fpregs->prfpreg.fpc));
	memcpy(&dst->fpregs.fprs, &fpregs->prfpreg.fprs, sizeof(fpregs->prfpreg.fprs));
	if (fpregs->flags & USER_FPREGS_VXRS) {
		memcpy(&dst_ext->vxrs_low, &fpregs->vxrs_low, sizeof(fpregs->vxrs_low));
		memcpy(&dst_ext->vxrs_high, &fpregs->vxrs_high, sizeof(fpregs->vxrs_high));
	} else {
		memset(&dst_ext->vxrs_low, 0, sizeof(dst_ext->vxrs_low));
		memset(&dst_ext->vxrs_high, 0, sizeof(dst_ext->vxrs_high));
	}
	return 0;
}

int sigreturn_prep_fpu_frame_plain(struct rt_sigframe *sigframe, struct rt_sigframe *rsigframe)
{
	return 0;
}

/*
 * Rewind the psw for 'bytes' bytes
 */
static inline void rewind_psw(psw_t *psw, unsigned long bytes)
{
	unsigned long mask;

	pr_debug("Rewind psw: %016lx bytes=%lu\n", psw->addr, bytes);
	mask = (psw->mask & PSW_MASK_EA) ? -1UL : (psw->mask & PSW_MASK_BA) ? (1UL << 31) - 1 : (1UL << 24) - 1;
	psw->addr = (psw->addr - bytes) & mask;
}

/*
 * Get vector registers
 */
int get_vx_regs(pid_t pid, user_fpregs_struct_t *fpregs)
{
	struct iovec iov;

	fpregs->flags &= ~USER_FPREGS_VXRS;
	iov.iov_base = &fpregs->vxrs_low;
	iov.iov_len = sizeof(fpregs->vxrs_low);
	if (ptrace(PTRACE_GETREGSET, pid, NT_S390_VXRS_LOW, &iov) < 0) {
		/*
		 * If the kernel does not support vector registers, we get
		 * EINVAL. With kernel support and old hardware, we get ENODEV.
		 */
		if (errno == EINVAL || errno == ENODEV) {
			memset(fpregs->vxrs_low, 0, sizeof(fpregs->vxrs_low));
			memset(fpregs->vxrs_high, 0, sizeof(fpregs->vxrs_high));
			pr_debug("VXRS registers not supported\n");
			return 0;
		}
		pr_perror("Couldn't get VXRS_LOW");
		return -1;
	}
	iov.iov_base = &fpregs->vxrs_high;
	iov.iov_len = sizeof(fpregs->vxrs_high);
	if (ptrace(PTRACE_GETREGSET, pid, NT_S390_VXRS_HIGH, &iov) < 0) {
		pr_perror("Couldn't get VXRS_HIGH");
		return -1;
	}
	fpregs->flags |= USER_FPREGS_VXRS;
	return 0;
}

/*
 * Get guarded-storage control block
 */
int get_gs_cb(pid_t pid, user_fpregs_struct_t *fpregs)
{
	struct iovec iov;

	fpregs->flags &= ~(USER_GS_CB | USER_GS_BC);
	iov.iov_base = &fpregs->gs_cb;
	iov.iov_len = sizeof(fpregs->gs_cb);
	if (ptrace(PTRACE_GETREGSET, pid, NT_S390_GS_CB, &iov) < 0) {
		switch (errno) {
		case EINVAL:
		case ENODEV:
			memset(&fpregs->gs_cb, 0, sizeof(fpregs->gs_cb));
			memset(&fpregs->gs_bc, 0, sizeof(fpregs->gs_bc));
			pr_debug("GS_CB not supported\n");
			return 0;
		case ENODATA:
			pr_debug("GS_CB not set\n");
			break;
		default:
			return -1;
		}
	} else {
		fpregs->flags |= USER_GS_CB;
	}
	iov.iov_base = &fpregs->gs_bc;
	iov.iov_len = sizeof(fpregs->gs_bc);
	if (ptrace(PTRACE_GETREGSET, pid, NT_S390_GS_BC, &iov) < 0) {
		if (errno == ENODATA) {
			pr_debug("GS_BC not set\n");
			return 0;
		}
		pr_perror("Couldn't get GS_BC");
		return -1;
	}
	fpregs->flags |= USER_GS_BC;

	return 0;
}

/*
 * Get runtime-instrumentation control block
 */
int get_ri_cb(pid_t pid, user_fpregs_struct_t *fpregs)
{
	user_regs_struct_t regs;
	struct iovec iov;
	psw_t *psw;

	fpregs->flags &= ~(USER_RI_CB | USER_RI_ON);
	iov.iov_base = &fpregs->ri_cb;
	iov.iov_len = sizeof(fpregs->ri_cb);
	if (ptrace(PTRACE_GETREGSET, pid, NT_S390_RI_CB, &iov) < 0) {
		switch (errno) {
		case EINVAL:
		case ENODEV:
			memset(&fpregs->ri_cb, 0, sizeof(fpregs->ri_cb));
			pr_debug("RI_CB not supported\n");
			return 0;
		case ENODATA:
			pr_debug("RI_CB not set\n");
			return 0;
		default:
			pr_perror("Couldn't get RI_CB");
			return -1;
		}
	}
	fpregs->flags |= USER_RI_CB;

	/* Get PSW and check if runtime-instrumentation bit is enabled */
	iov.iov_base = &regs.prstatus;
	iov.iov_len = sizeof(regs.prstatus);
	if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
		return -1;
	psw = &regs.prstatus.psw;
	if (psw->mask & PSW_MASK_RI)
		fpregs->flags |= USER_RI_ON;

	return 0;
}

/*
 * Disable runtime-instrumentation bit
 */
static int s390_disable_ri_bit(pid_t pid, user_regs_struct_t *regs)
{
	struct iovec iov;
	psw_t *psw;

	iov.iov_base = &regs->prstatus;
	iov.iov_len = sizeof(regs->prstatus);
	psw = &regs->prstatus.psw;
	psw->mask &= ~PSW_MASK_RI;
	return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}

/*
 * Prepare task registers for restart
 */
int compel_get_task_regs(pid_t pid, user_regs_struct_t *regs, user_fpregs_struct_t *ext_regs, save_regs_t save,
			 void *arg, __maybe_unused unsigned long flags)
{
	user_fpregs_struct_t tmp, *fpregs = ext_regs ? ext_regs : &tmp;
	struct iovec iov;
	int rewind;

	print_user_regs_struct("compel_get_task_regs", pid, regs);

	memset(fpregs, 0, sizeof(*fpregs));
	iov.iov_base = &fpregs->prfpreg;
	iov.iov_len = sizeof(fpregs->prfpreg);
	if (ptrace(PTRACE_GETREGSET, pid, NT_PRFPREG, &iov) < 0) {
		pr_perror("Couldn't get floating-point registers");
		return -1;
	}
	if (get_vx_regs(pid, fpregs)) {
		pr_perror("Couldn't get vector registers");
		return -1;
	}
	if (get_gs_cb(pid, fpregs)) {
		pr_perror("Couldn't get guarded-storage");
		return -1;
	}
	if (get_ri_cb(pid, fpregs)) {
		pr_perror("Couldn't get runtime-instrumentation");
		return -1;
	}
	/*
	 * If the runtime-instrumentation bit is set, we have to disable it
	 * before we execute parasite code. Otherwise parasite operations
	 * would be recorded.
	 */
	if (fpregs->flags & USER_RI_ON)
		s390_disable_ri_bit(pid, regs);

	print_user_fpregs_struct("compel_get_task_regs", pid, fpregs);
	/* Check for system call restarting. */
	if (regs->system_call) {
		rewind = regs->system_call >> 16;
		/* see arch/s390/kernel/signal.c: do_signal() */
		switch ((long)regs->prstatus.gprs[2]) {
		case -ERESTARTNOHAND:
		case -ERESTARTSYS:
		case -ERESTARTNOINTR:
			regs->prstatus.gprs[2] = regs->prstatus.orig_gpr2;
			rewind_psw(&regs->prstatus.psw, rewind);
			pr_debug("New gpr2: %016lx\n", regs->prstatus.gprs[2]);
			break;
		case -ERESTART_RESTARTBLOCK:
			pr_warn("Will restore %d with interrupted system call\n", pid);
			regs->prstatus.gprs[2] = -EINTR;
			break;
		}
	}
	/* Call save_task_regs() */
	return save(arg, regs, fpregs);
}

int compel_set_task_ext_regs(pid_t pid, user_fpregs_struct_t *ext_regs)
{
	struct iovec iov;
	int ret = 0;

	iov.iov_base = &ext_regs->prfpreg;
	iov.iov_len = sizeof(ext_regs->prfpreg);
	if (ptrace(PTRACE_SETREGSET, pid, NT_PRFPREG, &iov) < 0) {
		pr_perror("Couldn't set floating-point registers");
		ret = -1;
	}

	if (ext_regs->flags & USER_FPREGS_VXRS) {
		iov.iov_base = &ext_regs->vxrs_low;
		iov.iov_len = sizeof(ext_regs->vxrs_low);
		if (ptrace(PTRACE_SETREGSET, pid, NT_S390_VXRS_LOW, &iov) < 0) {
			pr_perror("Couldn't set VXRS_LOW");
			ret = -1;
		}

		iov.iov_base = &ext_regs->vxrs_high;
		iov.iov_len = sizeof(ext_regs->vxrs_high);
		if (ptrace(PTRACE_SETREGSET, pid, NT_S390_VXRS_HIGH, &iov) < 0) {
			pr_perror("Couldn't set VXRS_HIGH");
			ret = -1;
		}
	}

	if (ext_regs->flags & USER_GS_CB) {
		iov.iov_base = &ext_regs->gs_cb;
		iov.iov_len = sizeof(ext_regs->gs_cb);
		if (ptrace(PTRACE_SETREGSET, pid, NT_S390_GS_CB, &iov) < 0) {
			pr_perror("Couldn't set GS_CB");
			ret = -1;
		}
		iov.iov_base = &ext_regs->gs_bc;
		iov.iov_len = sizeof(ext_regs->gs_bc);
		if (ptrace(PTRACE_SETREGSET, pid, NT_S390_GS_BC, &iov) < 0) {
			pr_perror("Couldn't set GS_BC");
			ret = -1;
		}
	}

	if (ext_regs->flags & USER_RI_CB) {
		iov.iov_base = &ext_regs->ri_cb;
		iov.iov_len = sizeof(ext_regs->ri_cb);
		if (ptrace(PTRACE_SETREGSET, pid, NT_S390_RI_CB, &iov) < 0) {
			pr_perror("Couldn't set RI_CB");
			ret = -1;
		}
	}

	return ret;
}

/*
 * Injected syscall instruction
 */
const char code_syscall[] = {
	0x0a, 0x00, /* sc 0 */
	0x00, 0x01, /* S390_BREAKPOINT_U16 */
	0x00, 0x01, /* S390_BREAKPOINT_U16 */
	0x00, 0x01, /* S390_BREAKPOINT_U16 */
};

static inline void __check_code_syscall(void)
{
	BUILD_BUG_ON(sizeof(code_syscall) != BUILTIN_SYSCALL_SIZE);
	BUILD_BUG_ON(!is_log2(sizeof(code_syscall)));
}

/*
 * Issue s390 system call
 */
int compel_syscall(struct parasite_ctl *ctl, int nr, long *ret, unsigned long arg1, unsigned long arg2,
		   unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6)
{
	user_regs_struct_t regs = ctl->orig.regs;
	int err;

	/* Load syscall number into %r1 */
	regs.prstatus.gprs[1] = (unsigned long)nr;
	/* Load parameter registers %r2-%r7 */
	regs.prstatus.gprs[2] = arg1;
	regs.prstatus.gprs[3] = arg2;
	regs.prstatus.gprs[4] = arg3;
	regs.prstatus.gprs[5] = arg4;
	regs.prstatus.gprs[6] = arg5;
	regs.prstatus.gprs[7] = arg6;

	err = compel_execute_syscall(ctl, &regs, (char *)code_syscall);

	/* Return code from system is in %r2 */
	if (ret)
		*ret = regs.prstatus.gprs[2];
	return err;
}

/*
 * Issue s390 mmap call
 */
void *remote_mmap(struct parasite_ctl *ctl, void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	void *where = (void *)ctl->ictx.syscall_ip + BUILTIN_SYSCALL_SIZE;
	struct mmap_arg_struct arg_struct;
	pid_t pid = ctl->rpid;
	long map = 0;
	int err;

	/* Setup s390 mmap data */
	arg_struct.addr = (unsigned long)addr;
	arg_struct.len = length;
	arg_struct.prot = prot;
	arg_struct.flags = flags;
	arg_struct.fd = fd;
	arg_struct.offset = offset;

	/* Move args to process */
	if (ptrace_swap_area(pid, where, &arg_struct, sizeof(arg_struct))) {
		pr_err("Can't inject memfd args (pid: %d)\n", pid);
		return NULL;
	}

	/* Do syscall */
	err = compel_syscall(ctl, __NR_mmap, &map, (unsigned long)where, 0, 0, 0, 0, 0);
	if (err < 0 || (long)map < 0)
		map = 0;

	/* Restore data */
	if (ptrace_poke_area(pid, &arg_struct, where, sizeof(arg_struct))) {
		pr_err("Can't restore mmap args (pid: %d)\n", pid);
		if (map != 0) {
			err = compel_syscall(ctl, __NR_munmap, NULL, map, length, 0, 0, 0, 0);
			if (err)
				pr_err("Can't munmap %d\n", err);
			map = 0;
		}
	}

	return (void *)map;
}

/*
 * Setup registers for parasite call
 */
void parasite_setup_regs(unsigned long new_ip, void *stack, user_regs_struct_t *regs)
{
	regs->prstatus.psw.addr = new_ip;
	if (!stack)
		return;
	regs->prstatus.gprs[15] = ((unsigned long)stack) - STACK_FRAME_OVERHEAD;
}

/*
 * Check if we have all kernel and CRIU features to dump the task
 */
bool arch_can_dump_task(struct parasite_ctl *ctl)
{
	user_fpregs_struct_t fpregs;
	user_regs_struct_t regs;
	pid_t pid = ctl->rpid;
	char str[8];
	psw_t *psw;

	if (ptrace_get_regs(pid, &regs))
		return false;
	psw = &regs.prstatus.psw;
	/* Check if the kernel supports RI ptrace interface */
	if (psw->mask & PSW_MASK_RI) {
		if (get_ri_cb(pid, &fpregs) < 0) {
			pr_perror("Can't dump process with RI bit active");
			return false;
		}
	}
	/* We don't support 24 and 31 bit mode - only 64 bit */
	if (psw->mask & PSW_MASK_EA) {
		if (psw->mask & PSW_MASK_BA)
			return true;
		else
			sprintf(str, "??");
	} else {
		if (psw->mask & PSW_MASK_BA)
			sprintf(str, "31");
		else
			sprintf(str, "24");
	}
	pr_err("Pid %d is %s bit: Only 64 bit tasks are supported\n", pid, str);
	return false;
}

/*
 * Return current alternate signal stack
 */
int arch_fetch_sas(struct parasite_ctl *ctl, struct rt_sigframe *s)
{
	long ret;
	int err;

	err = compel_syscall(ctl, __NR_sigaltstack, &ret, 0, (unsigned long)&s->uc.uc_stack, 0, 0, 0, 0);
	return err ? err : ret;
}

/*
 * Find last mapped address of current process
 */
static unsigned long max_mapped_addr(void)
{
	unsigned long addr_end, addr_max = 0;
	char line[128];
	FILE *fp;

	fp = fopen("/proc/self/maps", "r");
	if (!fp)
		goto out;

	/* Parse lines like: 3fff415f000-3fff4180000 rw-p 00000000 00:00 0 */
	while (fgets(line, sizeof(line), fp)) {
		char *ptr;
		/* First skip start address */
		strtoul(&line[0], &ptr, 16);
		addr_end = strtoul(ptr + 1, NULL, 16);
		addr_max = max(addr_max, addr_end);
	}
	fclose(fp);
out:
	return addr_max - 1;
}

/*
 * Kernel task size level
 *
 * We have (dynamic) 4 level page tables for 64 bit since linux 2.6.25:
 *
 *  5a216a2083 ("[S390] Add four level page tables for CONFIG_64BIT=y.")
 *  6252d702c5 ("[S390] dynamic page tables.")
 *
 * The code below is already prepared for future (dynamic) 5 level page tables.
 *
 * Besides that there is one problematic kernel bug that has been fixed for
 * linux 4.11 by the following commit:
 *
 *  ee71d16d22 ("s390/mm: make TASK_SIZE independent from the number
 *              of page table levels")
 *
 * A 64 bit process on s390x always starts with 3 levels and upgrades to 4
 * levels for mmap(> 4 TB) and to 5 levels for mmap(> 16 EB).
 *
 * Unfortunately before fix ee71d16d22 for a 3 level process munmap()
 * and mremap() fail for addresses > 4 TB. CRIU uses the task size,
 * to unmap() all memory from a starting point to task size to get rid of
 * unwanted mappings. CRIU uses mremap() to establish the final mappings
 * which also fails if we want to restore mappings > 4 TB and the initial
 * restore process still runs with 3 levels.
 *
 * To support the current CRIU design on s390 we return task size = 4 TB when
 * a kernel without fix ee71d16d22 is detected. In this case we can dump at
 * least processes with < 4 TB which is the most likely case anyway.
 *
 * For kernels with fix ee71d16d22 we are fully functional.
 */
enum kernel_ts_level {
	/* Kernel with 4 level page tables without fix ee71d16d22 */
	KERNEL_TS_LEVEL_4_FIX_NO,
	/* Kernel with 4 level page tables with fix ee71d16d22 */
	KERNEL_TS_LEVEL_4_FIX_YES,
	/* Kernel with 4 level page tables with or without fix ee71d16d22 */
	KERNEL_TS_LEVEL_4_FIX_UNKN,
	/* Kernel with 5 level page tables */
	KERNEL_TS_LEVEL_5,
};

/* See arch/s390/include/asm/processor.h */
#define TASK_SIZE_LEVEL_3 0x40000000000UL      /* 4 TB */
#define TASK_SIZE_LEVEL_4 0x20000000000000UL   /* 8 PB */
#define TASK_SIZE_LEVEL_5 0xffffffffffffefffUL /* 16 EB - 0x1000 */

/*
 * Return detected kernel version regarding task size level
 *
 * We use unmap() to probe the maximum possible page table level of kernel
 */
static enum kernel_ts_level get_kernel_ts_level(void)
{
	unsigned long criu_end_addr = max_mapped_addr();

	/* Check for 5 levels */
	if (criu_end_addr >= TASK_SIZE_LEVEL_4)
		return KERNEL_TS_LEVEL_5;
	else if (munmap((void *)TASK_SIZE_LEVEL_4, 0x1000) == 0)
		return KERNEL_TS_LEVEL_5;

	if (criu_end_addr < TASK_SIZE_LEVEL_3) {
		/* Check for 4 level kernel with fix */
		if (munmap((void *)TASK_SIZE_LEVEL_3, 0x1000) == 0)
			return KERNEL_TS_LEVEL_4_FIX_YES;
		else
			return KERNEL_TS_LEVEL_4_FIX_NO;
	}
	/* We can't find out if kernel has the fix */
	return KERNEL_TS_LEVEL_4_FIX_UNKN;
}

/*
 * Log detected level
 */
static void pr_levels(const char *str)
{
	pr_debug("Max user page table levels (task size): %s\n", str);
}

/*
 * Return last address (+1) of biggest possible user address space for
 * current kernel
 */
unsigned long compel_task_size(void)
{
	switch (get_kernel_ts_level()) {
	case KERNEL_TS_LEVEL_4_FIX_NO:
		pr_levels("KERNEL_TS_LEVEL_4_FIX_NO");
		return TASK_SIZE_LEVEL_3;
	case KERNEL_TS_LEVEL_4_FIX_YES:
		pr_levels("KERNEL_TS_LEVEL_4_FIX_YES");
		return TASK_SIZE_LEVEL_4;
	case KERNEL_TS_LEVEL_4_FIX_UNKN:
		pr_levels("KERNEL_TS_LEVEL_4_FIX_UNKN");
		return TASK_SIZE_LEVEL_3;
	default: /* KERNEL_TS_LEVEL_5 */
		pr_levels("KERNEL_TS_LEVEL_5");
		return TASK_SIZE_LEVEL_5;
	}
}

/*
 * Get task registers (overwrites weak function)
 */
int ptrace_get_regs(int pid, user_regs_struct_t *regs)
{
	struct iovec iov;
	int rc;

	pr_debug("ptrace_get_regs: pid=%d\n", pid);

	iov.iov_base = &regs->prstatus;
	iov.iov_len = sizeof(regs->prstatus);
	rc = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
	if (rc != 0)
		return rc;

	iov.iov_base = &regs->system_call;
	iov.iov_len = sizeof(regs->system_call);
	return ptrace(PTRACE_GETREGSET, pid, NT_S390_SYSTEM_CALL, &iov);
}

/*
 * Set task registers (overwrites weak function)
 */
int ptrace_set_regs(int pid, user_regs_struct_t *regs)
{
	uint32_t system_call = 0;
	struct iovec iov;
	int rc;

	pr_debug("ptrace_set_regs: pid=%d\n", pid);

	iov.iov_base = &regs->prstatus;
	iov.iov_len = sizeof(regs->prstatus);
	rc = ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
	if (rc)
		return rc;

	/*
	 * If we attached to an inferior that is sleeping in a restarting
	 * system call like futex_wait(), we have to reset the system_call
	 * to 0. Otherwise the kernel would try to finish the interrupted
	 * system call after PTRACE_CONT and we could not run the
	 * parasite code.
	 */
	iov.iov_base = &system_call;
	iov.iov_len = sizeof(system_call);
	return ptrace(PTRACE_SETREGSET, pid, NT_S390_SYSTEM_CALL, &iov);
}
