#include <unistd.h>

#include "restorer.h"
#include "asm/restorer.h"
#include "asm/memcpy_64.h"

#include "syscall.h"
#include "log.h"
#include "asm/fpu.h"
#include "cpu.h"

int restore_gpregs(struct rt_sigframe *f, UserArmRegsEntry *r)
{
#define CPREG1(d)       f->sig.uc.uc_mcontext.arm_##d = r->d
#define CPREG2(d, s)    f->sig.uc.uc_mcontext.arm_##d = r->s

	CPREG1(r0);
	CPREG1(r1);
	CPREG1(r2);
	CPREG1(r3);
	CPREG1(r4);
	CPREG1(r5);
	CPREG1(r6);
	CPREG1(r7);
	CPREG1(r8);
	CPREG1(r9);
	CPREG1(r10);
	CPREG1(fp);
	CPREG1(ip);
	CPREG1(sp);
	CPREG1(lr);
	CPREG1(pc);
	CPREG1(cpsr);

#undef CPREG1
#undef CPREG2

	return 0;
}

int restore_fpu(struct rt_sigframe *sigframe, struct thread_restore_args *args)
{
	struct aux_sigframe *aux = (struct aux_sigframe *)&sigframe->sig.uc.uc_regspace;

	aux->vfp.magic = VFP_MAGIC;
	aux->vfp.size = VFP_STORAGE_SIZE;
	builtin_memcpy(&aux->vfp.ufp, &args->fpu_state.ufp, sizeof(aux->vfp.ufp));

	return 0;
}
