#include <sys/types.h>
#include <sys/uio.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <errno.h>

#include <compel/asm/fpu.h>
#include <compel/cpu.h>
#include "errno.h"
#include <compel/plugins/std/syscall-codes.h>
#include <compel/plugins/std/syscall.h>
#include "common/err.h"
#include "common/page.h"
#include "asm/infect-types.h"
#include "ptrace.h"
#include "infect.h"
#include "infect-priv.h"
#include "log.h"
#include "common/bug.h"

/*
 * Injected syscall instruction
 * mips64el is Little Endian
 */
const char code_syscall[] = {
	0x0c, 0x00, 0x00, 0x00, /* syscall    */
	0x0d, 0x00, 0x00, 0x00	/*  break      */
};

/* 10-byte legacy floating point register */
struct fpreg {
	uint16_t significand[4];
	uint16_t exponent;
};

/* 16-byte floating point register */
struct fpxreg {
	uint16_t significand[4];
	uint16_t exponent;
	uint16_t padding[3];
};

int sigreturn_prep_regs_plain(struct rt_sigframe *sigframe, user_regs_struct_t *regs, user_fpregs_struct_t *fpregs)
{
	sigframe->rs_uc.uc_mcontext.sc_regs[0] = regs->regs[0];
	sigframe->rs_uc.uc_mcontext.sc_regs[1] = regs->regs[1];
	sigframe->rs_uc.uc_mcontext.sc_regs[2] = regs->regs[2];
	sigframe->rs_uc.uc_mcontext.sc_regs[3] = regs->regs[3];
	sigframe->rs_uc.uc_mcontext.sc_regs[4] = regs->regs[4];
	sigframe->rs_uc.uc_mcontext.sc_regs[5] = regs->regs[5];
	sigframe->rs_uc.uc_mcontext.sc_regs[6] = regs->regs[6];
	sigframe->rs_uc.uc_mcontext.sc_regs[7] = regs->regs[7];
	sigframe->rs_uc.uc_mcontext.sc_regs[8] = regs->regs[8];
	sigframe->rs_uc.uc_mcontext.sc_regs[9] = regs->regs[9];
	sigframe->rs_uc.uc_mcontext.sc_regs[10] = regs->regs[10];
	sigframe->rs_uc.uc_mcontext.sc_regs[11] = regs->regs[11];
	sigframe->rs_uc.uc_mcontext.sc_regs[12] = regs->regs[12];
	sigframe->rs_uc.uc_mcontext.sc_regs[13] = regs->regs[13];
	sigframe->rs_uc.uc_mcontext.sc_regs[14] = regs->regs[14];
	sigframe->rs_uc.uc_mcontext.sc_regs[15] = regs->regs[15];
	sigframe->rs_uc.uc_mcontext.sc_regs[16] = regs->regs[16];
	sigframe->rs_uc.uc_mcontext.sc_regs[17] = regs->regs[17];
	sigframe->rs_uc.uc_mcontext.sc_regs[18] = regs->regs[18];
	sigframe->rs_uc.uc_mcontext.sc_regs[19] = regs->regs[19];
	sigframe->rs_uc.uc_mcontext.sc_regs[20] = regs->regs[20];
	sigframe->rs_uc.uc_mcontext.sc_regs[21] = regs->regs[21];
	sigframe->rs_uc.uc_mcontext.sc_regs[22] = regs->regs[22];
	sigframe->rs_uc.uc_mcontext.sc_regs[23] = regs->regs[23];
	sigframe->rs_uc.uc_mcontext.sc_regs[24] = regs->regs[24];
	sigframe->rs_uc.uc_mcontext.sc_regs[25] = regs->regs[25];
	sigframe->rs_uc.uc_mcontext.sc_regs[26] = regs->regs[26];
	sigframe->rs_uc.uc_mcontext.sc_regs[27] = regs->regs[27];
	sigframe->rs_uc.uc_mcontext.sc_regs[28] = regs->regs[28];
	sigframe->rs_uc.uc_mcontext.sc_regs[29] = regs->regs[29];
	sigframe->rs_uc.uc_mcontext.sc_regs[30] = regs->regs[30];
	sigframe->rs_uc.uc_mcontext.sc_regs[31] = regs->regs[31];
	sigframe->rs_uc.uc_mcontext.sc_mdlo = regs->lo;
	sigframe->rs_uc.uc_mcontext.sc_mdhi = regs->hi;
	sigframe->rs_uc.uc_mcontext.sc_pc = regs->cp0_epc;

	sigframe->rs_uc.uc_mcontext.sc_fpregs[0] = fpregs->regs[0];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[1] = fpregs->regs[1];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[2] = fpregs->regs[2];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[3] = fpregs->regs[3];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[4] = fpregs->regs[4];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[5] = fpregs->regs[5];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[6] = fpregs->regs[6];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[7] = fpregs->regs[7];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[8] = fpregs->regs[8];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[9] = fpregs->regs[9];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[10] = fpregs->regs[10];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[11] = fpregs->regs[11];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[12] = fpregs->regs[12];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[13] = fpregs->regs[13];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[14] = fpregs->regs[14];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[15] = fpregs->regs[15];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[16] = fpregs->regs[16];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[17] = fpregs->regs[17];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[18] = fpregs->regs[18];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[19] = fpregs->regs[19];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[20] = fpregs->regs[20];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[21] = fpregs->regs[21];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[22] = fpregs->regs[22];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[23] = fpregs->regs[23];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[24] = fpregs->regs[24];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[25] = fpregs->regs[25];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[26] = fpregs->regs[26];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[27] = fpregs->regs[27];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[28] = fpregs->regs[28];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[29] = fpregs->regs[29];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[30] = fpregs->regs[30];
	sigframe->rs_uc.uc_mcontext.sc_fpregs[31] = fpregs->regs[31];

	return 0;
}

int sigreturn_prep_fpu_frame_plain(struct rt_sigframe *sigframe, struct rt_sigframe *rsigframe)
{
	return 0;
}

int compel_get_task_regs(pid_t pid, user_regs_struct_t *regs, user_fpregs_struct_t *ext_regs, save_regs_t save,
			 void *arg, __maybe_unused unsigned long flags)
{
	user_fpregs_struct_t xsave = {}, *xs = ext_regs ? ext_regs : &xsave;
	int ret = -1;

	pr_info("Dumping GP/FPU registers for %d\n", pid);

	if (ptrace(PTRACE_GETFPREGS, pid, NULL, xs)) {
		pr_perror("Can't obtain FPU registers for %d", pid);
		return ret;
	}

	/*Restart the system call*/
	if (regs->regs[0]) {
		switch ((long)(int)regs->regs[2]) {
		case ERESTARTNOHAND:
		case ERESTARTSYS:
		case ERESTARTNOINTR:
			regs->regs[2] = regs->regs[0];
			regs->regs[7] = regs->regs[26];
			regs->cp0_epc -= 4;
			break;
		case ERESTART_RESTARTBLOCK:
			pr_warn("Will restore %d with interrupted system call\n", pid);
			regs->regs[2] = -EINTR;
			break;
		}
		regs->regs[0] = 0;
	}

	ret = save(arg, regs, xs);
	return ret;
}

int compel_set_task_ext_regs(pid_t pid, user_fpregs_struct_t *ext_regs)
{
	pr_info("Restoring GP/FPU registers for %d\n", pid);

	if (ptrace(PTRACE_SETFPREGS, pid, NULL, ext_regs)) {
		pr_perror("Can't set FPU registers for %d", pid);
		return -1;
	}
	return 0;
}

int compel_syscall(struct parasite_ctl *ctl, int nr, long *ret, unsigned long arg1, unsigned long arg2,
		   unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6)
{
	/*refer to glibc-2.20/sysdeps/unix/sysv/linux/mips/mips64/syscall.S*/
	user_regs_struct_t regs = ctl->orig.regs;
	int err;

	regs.regs[2] = (unsigned long)nr; //syscall_number will be in v0
	regs.regs[4] = arg1;
	regs.regs[5] = arg2;
	regs.regs[6] = arg3;
	regs.regs[7] = arg4;
	regs.regs[8] = arg5;
	regs.regs[9] = arg6;

	err = compel_execute_syscall(ctl, &regs, code_syscall);
	*ret = regs.regs[2];

	return err;
}

void *remote_mmap(struct parasite_ctl *ctl, void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	long map;
	int err;

	err = compel_syscall(ctl, __NR_mmap, &map, (unsigned long)addr, length, prot, flags, fd, offset >> PAGE_SHIFT);

	if (err < 0 || IS_ERR_VALUE(map)) {
		pr_err("remote mmap() failed: %s\n", strerror(-map));
		return NULL;
	}

	return (void *)map;
}

/*
 * regs must be inited when calling this function from original context
 */
void parasite_setup_regs(unsigned long new_ip, void *stack, user_regs_struct_t *regs)
{
	regs->cp0_epc = new_ip;
	if (stack) {
		/* regs[29] is sp */
		regs->regs[29] = (unsigned long)stack;
	}
}

bool arch_can_dump_task(struct parasite_ctl *ctl)
{
	return true;
}

int arch_fetch_sas(struct parasite_ctl *ctl, struct rt_sigframe *s)
{
	long ret;
	int err;

	err = compel_syscall(ctl, __NR_sigaltstack, &ret, 0, (unsigned long)&s->rs_uc.uc_stack, 0, 0, 0, 0);
	return err ? err : ret;
}

int ptrace_set_breakpoint(pid_t pid, void *addr)
{
	return 0;
}

int ptrace_flush_breakpoints(pid_t pid)
{
	return 0;
}

/*refer to kernel linux-3.10/arch/mips/include/asm/processor.h*/
#define TASK_SIZE32 0x7fff8000UL
#define TASK_SIZE64 0x10000000000UL
#define TASK_SIZE   TASK_SIZE64

unsigned long compel_task_size(void)
{
	return TASK_SIZE;
}

/*
 * Get task registers (overwrites weak function)
 *
 */
int ptrace_get_regs(int pid, user_regs_struct_t *regs)
{
	return ptrace(PTRACE_GETREGS, pid, NULL, regs);
}

/*
 * Set task registers (overwrites weak function)
 */
int ptrace_set_regs(int pid, user_regs_struct_t *regs)
{
	return ptrace(PTRACE_SETREGS, pid, NULL, regs);
}

void compel_relocs_apply_mips(void *mem, void *vbase, struct parasite_blob_desc *pbd)
{
	compel_reloc_t *elf_relocs = pbd->hdr.relocs;
	size_t nr_relocs = pbd->hdr.nr_relocs;
	size_t i, j;

	/*
	 * mips rebasing :load time relocation
	 * parasite.built-in.o and restorer.built-in.o is ELF 64-bit LSB relocatable for mips.
	 * so we have to relocate some type for R_MIPS_26 R_MIPS_HIGHEST R_MIPS_HIGHER R_MIPS_HI16 and R_MIPS_LO16 in there.
	 * for mips64el .if toload/store data or jump instruct ,need to relocation R_TYPE
	 */
	for (i = 0, j = 0; i < nr_relocs; i++) {
		if (elf_relocs[i].type & COMPEL_TYPE_MIPS_26) {
			int *where = (mem + elf_relocs[i].offset);
			*where = *where |
				 ((elf_relocs[i].addend + ((unsigned long)vbase & 0x00fffffff) /*low 28 bit*/) >> 2);
		} else if (elf_relocs[i].type & COMPEL_TYPE_MIPS_64) {
			unsigned long *where = (mem + elf_relocs[i].offset);
			*where = elf_relocs[i].addend + (unsigned long)vbase;
		} else if (elf_relocs[i].type & COMPEL_TYPE_MIPS_HI16) {
			/* refer to binutils mips.cc */
			int *where = (mem + elf_relocs[i].offset);
			int v_lo16 = (unsigned long)vbase & 0x00ffff;

			if ((v_lo16 + elf_relocs[i].value + elf_relocs[i].addend) >= 0x8000) {
				*where = *where | ((((unsigned long)vbase >> 16) & 0xffff) + 0x1);
			} else {
				*where = *where | ((((unsigned long)vbase >> 16) & 0xffff));
			}
		} else if (elf_relocs[i].type & COMPEL_TYPE_MIPS_LO16) {
			int *where = (mem + elf_relocs[i].offset);
			int v_lo16 = (unsigned long)vbase & 0x00ffff;
			*where = *where | ((v_lo16 + elf_relocs[i].addend) & 0xffff);
		} else if (elf_relocs[i].type & COMPEL_TYPE_MIPS_HIGHER) {
			int *where = (mem + elf_relocs[i].offset);
			*where = *where | ((((unsigned long)vbase + (uint64_t)0x80008000) >> 32) & 0xffff);
		} else if (elf_relocs[i].type & COMPEL_TYPE_MIPS_HIGHEST) {
			int *where = (mem + elf_relocs[i].offset);
			*where = *where | ((((unsigned long)vbase + (uint64_t)0x800080008000llu) >> 48) & 0xffff);
		} else {
			BUG();
		}
	}
}
