#include <stdlib.h>
#include <stdint.h>

#include "asm/sigframe.h"
#include "asm/types.h"

#include "log.h"

int sigreturn_prep_fpu_frame(struct rt_sigframe *sigframe,
			     struct rt_sigframe *rsigframe)
{
	fpu_state_t *fpu_state = RT_SIGFRAME_FPU(rsigframe);
	unsigned long addr = (unsigned long)(void *)&fpu_state->xsave;

	if ((addr % 64ul) == 0ul) {
		sigframe->uc.uc_mcontext.fpstate = &fpu_state->xsave;
	} else {
		pr_err("Unaligned address passed: %lx\n", addr);
		return -1;
	}

	return 0;
}
