#include <sys/types.h>
#include <sys/uio.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/user.h>

#include <compel/asm/fpu.h>

#include "asm/cpu.h"

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
 * mips64el 是64位小端字节序
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
    pr_info("ERROR''''''''%s:%d:no implemented!!\n",__FILE__,__LINE__);
	return 0;
}

int sigreturn_prep_fpu_frame_plain(struct rt_sigframe *sigframe,
				   struct rt_sigframe *rsigframe)
{
    pr_info("ERROR''''''''%s:%d:no implemented!!\n",__FILE__,__LINE__);
	return 0;
}

int get_task_regs(pid_t pid, user_regs_struct_t *regs, save_regs_t save,
		  void *arg)
{
    pr_info("''''''''%s:%d\n",__FILE__,__LINE__);
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

/*LOONGSON MIPS PAGE_SIZE IS 16K */

	err = compel_syscall(ctl, __NR_mmap, &map,
			(unsigned long)addr, length, prot, flags, fd, offset >> 14);
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

#define USER32_CS	0x23
#define USER_CS		0x33
#if 0 //fixme: gysun
static bool ldt_task_selectors(pid_t pid)
{
    pr_info("ERROR''''''''%s:%d:no implemented!!\n",__FILE__,__LINE__);

	unsigned long cs;

	errno = 0;
	/*
	 * Offset of register must be from 64-bit set even for
	 * compatible tasks. Fix this to support native i386 tasks
	 */
	cs = ptrace(PTRACE_PEEKUSER, pid, offsetof(user_regs_struct64, cs), 0);
	if (errno != 0) {
		pr_perror("Can't get CS register for %d", pid);
		return -1;
	}

	return cs != USER_CS && cs != USER32_CS;
//	return -1;
}
#endif

bool arch_can_dump_task(struct parasite_ctl *ctl)
{
	/*
	 * TODO: Add proper check here
	 */
	return true;
}

int arch_fetch_sas(struct parasite_ctl *ctl, struct rt_sigframe *s)
{
    pr_info("''''''''%s:%d\n",__FILE__,__LINE__);
    long ret;
    int err;

    err = compel_syscall(ctl, __NR_sigaltstack,
			 &ret, 0, (unsigned long)&s->rs_uc.uc_stack,
			 0, 0, 0, 0);
    return err ? err : ret;
}

/* Copied from the gdb header gdb/nat/x86-dregs.h */

/* Debug registers' indices.  */
#define DR_FIRSTADDR 0
#define DR_LASTADDR  3
#define DR_NADDR     4  /* The number of debug address registers.  */
#define DR_STATUS    6  /* Index of debug status register (DR6).  */
#define DR_CONTROL   7  /* Index of debug control register (DR7).  */

#define DR_LOCAL_ENABLE_SHIFT   0 /* Extra shift to the local enable bit.  */
#define DR_GLOBAL_ENABLE_SHIFT  1 /* Extra shift to the global enable bit.  */
#define DR_ENABLE_SIZE          2 /* Two enable bits per debug register.  */

/* Locally enable the break/watchpoint in the I'th debug register.  */
#define X86_DR_LOCAL_ENABLE(i) (1 << (DR_LOCAL_ENABLE_SHIFT + DR_ENABLE_SIZE * (i)))

int ptrace_set_breakpoint(pid_t pid, void *addr)
{
    pr_info("ERROR''''''''%s:%d:no implemented!!\n",__FILE__,__LINE__);
#if 0 //fixme: gysun
	int ret;
	/* Set a breakpoint */
	if (ptrace(PTRACE_POKEUSER, pid,
			offsetof(struct user, u_debugreg[DR_FIRSTADDR]),
			addr)) {
		pr_perror("Unable to setup a breakpoint into %d", pid);
		return -1;
	}

	/* Enable the breakpoint */
	if (ptrace(PTRACE_POKEUSER, pid,
			offsetof(struct user, u_debugreg[DR_CONTROL]),
			X86_DR_LOCAL_ENABLE(DR_FIRSTADDR))) {
		pr_perror("Unable to enable the breakpoint for %d", pid);
		return -1;
	}

	ret = ptrace(PTRACE_CONT, pid, NULL, NULL);
	if (ret) {
		pr_perror("Unable to restart the  stopped tracee process %d", pid);
		return -1;
	}

#endif
	return 1;
}

int ptrace_flush_breakpoints(pid_t pid)
{
     pr_info("%s:%d:WARN:no implemented!!\n",__FILE__,__LINE__);
#if 0 //fixme: gysun
	/* Disable the breakpoint */
	if (ptrace(PTRACE_POKEUSER, pid,
			offsetof(struct user, u_debugreg[DR_CONTROL]),
			0)) {
		pr_perror("Unable to disable the breakpoint for %d", pid);
		return -1;
	}
#endif
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
