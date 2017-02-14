#include <stdlib.h>
#include <stdint.h>

#include "asm/sigframe.h"
#include "asm/types.h"

#include "log.h"

int sigreturn_prep_fpu_frame(struct rt_sigframe *sigframe,
		struct rt_sigframe *rsigframe)
{
	/*
	 * Use local sigframe to check native/compat type,
	 * but set address for rsigframe.
	 */
	fpu_state_t *fpu_state = (sigframe->is_native) ?
		&rsigframe->native.fpu_state :
		&rsigframe->compat.fpu_state;
	unsigned long addr = (unsigned long)(void *)&fpu_state->xsave;

	if (sigframe->is_native && (addr % 64ul) == 0ul) {
		sigframe->native.uc.uc_mcontext.fpstate = &fpu_state->xsave;
	} else if (!sigframe->is_native) {
		sigframe->compat.uc.uc_mcontext.fpstate = (uint32_t)addr;
	} else {
		pr_err("Unaligned address passed: %lx (native %d)\n",
		       addr, sigframe->is_native);
		return -1;
	}

	return 0;
}
