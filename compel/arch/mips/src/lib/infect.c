#include <sys/types.h>
#include <sys/uio.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/user.h>

#include <compel/asm/fpu.h>

//#include "asm/cpu.h"

//#include <compel/asm/processor-flags.h>
#include <compel/cpu.h>
#include "errno.h"
#include <compel/plugins/std/syscall-codes.h>
#include <compel/plugins/std/syscall.h>
#include "common/err.h"
#include "asm/infect-types.h"
#include "ptrace.h"
#include "infect.h"
#include "infect-priv.h"
#include "log.h"
#include <stdio.h>
/*
 * Injected syscall instruction
 * mips64el is Little Endian
 */
const char code_syscall[] = {
    0x0c, 0x00, 0x00, 0x00,   /* syscall    */
    0x0d, 0x00, 0x00, 0x00   /*  break      */
};

/* 10-byte legacy floating point register */
struct fpreg {
	uint16_t			significand[4];
	uint16_t			exponent;
};

/* 16-byte floating point register */
struct fpxreg {
	uint16_t			significand[4];
	uint16_t			exponent;
	uint16_t			padding[3];
};


int sigreturn_prep_regs_plain(struct rt_sigframe *sigframe,
			      user_regs_struct_t *regs,
			      user_fpregs_struct_t *fpregs)
{
    pr_warn("%s:%d:no implemented!!\n",__FILE__,__LINE__);
	return 0;
}

int sigreturn_prep_fpu_frame_plain(struct rt_sigframe *sigframe,
				   struct rt_sigframe *rsigframe)
{
    pr_warn("%s:%d:no implemented!!\n",__FILE__,__LINE__);
	return 0;
}

int get_task_regs(pid_t pid, user_regs_struct_t *regs, save_regs_t save,
		  void *arg, __maybe_unused unsigned long flags)
{
	user_fpregs_struct_t xsave	= {  }, *xs = NULL;
	int ret = -1;

	if (ptrace(PTRACE_GETFPREGS, pid, NULL, &xsave)) {
	    pr_perror("Can't obtain FPU registers for %d", pid);
	    return ret;
	}

	xs = &xsave;
	ret = save(arg, regs, xs);
	return ret;
}

int compel_syscall(struct parasite_ctl *ctl, int nr, long *ret,
		unsigned long arg1,
		unsigned long arg2,
		unsigned long arg3,
		unsigned long arg4,
		unsigned long arg5,
		unsigned long arg6)
{

/*from glibc-2.20/sysdeps/unix/sysv/linux/mips/mips64/syscall.S*/

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

void *remote_mmap(struct parasite_ctl *ctl,
		  void *addr, size_t length, int prot,
		  int flags, int fd, off_t offset)
{
	long map;
	int err;

	err = compel_syscall(ctl, __NR_mmap, &map,
			(unsigned long)addr, length, prot, flags, fd, offset >> PAGE_SHIFT);
	if (err < 0){
		map = 0;
	}
	return (void *)map;
}

/*
 * regs must be inited when calling this function from original context
 */
void parasite_setup_regs(unsigned long new_ip, void *stack, user_regs_struct_t *regs)
{  
    regs->cp0_epc = new_ip;
    if (stack){
	  //regs[29] is sp 
	regs->regs[29] = (unsigned long)stack;
    }
}

bool arch_can_dump_task(struct parasite_ctl *ctl)
{
	/*
	 * TODO: Add proper check here
	 */
	return true;
}

int arch_fetch_sas(struct parasite_ctl *ctl, struct rt_sigframe *s)
{
    long ret;
    int err;

    err = compel_syscall(ctl, __NR_sigaltstack,
			 &ret, 0, (unsigned long)&s->rs_uc.uc_stack,
			 0, 0, 0, 0);
    return err ? err : ret;
}


/* Debug registers' indices.  */
#define DR_FIRSTADDR 0
#define DR_LASTADDR  3
#define DR_NADDR     4  /* The number of debug address registers.  */
#define DR_STATUS    6  /* Index of debug status register (DR6).  */
#define DR_CONTROL   7  /* Index of debug control register (DR7).  */

#define DR_LOCAL_ENABLE_SHIFT   0 /* Extra shift to the local enable bit.  */
#define DR_GLOBAL_ENABLE_SHIFT  1 /* Extra shift to the global enable bit.  */
#define DR_ENABLE_SIZE          2 /* Two enable bits per debug register.  */

int ptrace_set_breakpoint(pid_t pid, void *addr)
{
    pr_warn("%s:%d:no implemented!!\n",__FILE__,__LINE__);
    return 1;
}

int ptrace_flush_breakpoints(pid_t pid)
{
     pr_warn("%s:%d:no implemented!!\n",__FILE__,__LINE__);
	return 0;
}

//#define TASK_SIZE	((1UL << 47) - PAGE_SIZE)

/*refer to kernel linux-3.10/arch/mips/include/asm/processor.h*/
#define TASK_SIZE32 0x7fff8000UL
#define TASK_SIZE64 0x10000000000UL
#define TASK_SIZE TASK_SIZE64
/*
 * Task size may be limited to 3G but we need a
 * higher limit, because it's backward compatible.
 */
#define TASK_SIZE_IA32	(0xffffe000)

unsigned long compel_task_size(void) { return TASK_SIZE; }
