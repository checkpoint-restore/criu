#include <unistd.h>

#include "restorer.h"
#include "asm/restorer.h"

#include "syscall.h"
#include "log.h"

int restore_gpregs(struct rt_sigframe *f, UserX86RegsEntry *r)
{
	long ret;
	unsigned long fsgs_base;

#define CPREG1(d)	f->uc.uc_mcontext.d = r->d
#define CPREG2(d, s)	f->uc.uc_mcontext.d = r->s

	CPREG1(r8);
	CPREG1(r9);
	CPREG1(r10);
	CPREG1(r11);
	CPREG1(r12);
	CPREG1(r13);
	CPREG1(r14);
	CPREG1(r15);
	CPREG2(rdi, di);
	CPREG2(rsi, si);
	CPREG2(rbp, bp);
	CPREG2(rbx, bx);
	CPREG2(rdx, dx);
	CPREG2(rax, ax);
	CPREG2(rcx, cx);
	CPREG2(rsp, sp);
	CPREG2(rip, ip);
	CPREG2(eflags, flags);
	CPREG1(cs);
	CPREG1(gs);
	CPREG1(fs);

	fsgs_base = r->fs_base;
	ret = sys_arch_prctl(ARCH_SET_FS, fsgs_base);
	if (ret) {
		pr_info("SET_FS fail %ld\n", ret);
		return -1;
	}

	fsgs_base = r->gs_base;
	ret = sys_arch_prctl(ARCH_SET_GS, fsgs_base);
	if (ret) {
		pr_info("SET_GS fail %ld\n", ret);
		return -1;
	}

	return 0;
}
