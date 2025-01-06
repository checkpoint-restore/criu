#include <stdlib.h>
#include <stdint.h>

#include "asm/sigframe.h"
#include "asm/types.h"

#include "log.h"
#include "common/bug.h"

/*
 * The signal frame has been built using local addresses. Since it has to be
 * used in the context of the checkpointed process, the v_regs pointer in the
 * signal frame must be updated to match the address in the remote stack.
 */
static inline void update_vregs(mcontext_t *lcontext, mcontext_t *rcontext)
{
	if (lcontext->v_regs) {
		uint64_t offset = (uint64_t)(lcontext->v_regs) - (uint64_t)lcontext;
		lcontext->v_regs = (vrregset_t *)((uint64_t)rcontext + offset);

		pr_debug("Updated v_regs:%llx (rcontext:%llx)\n", (unsigned long long)lcontext->v_regs,
			 (unsigned long long)rcontext);
	}
}

int sigreturn_prep_fpu_frame(struct rt_sigframe *frame, struct rt_sigframe *rframe)
{
	uint64_t msr = frame->uc.uc_mcontext.gp_regs[PT_MSR];

	update_vregs(&frame->uc.uc_mcontext, &rframe->uc.uc_mcontext);

	/* Sanity check: If TM so uc_link should be set, otherwise not */
	if (MSR_TM_ACTIVE(msr) ^ (!!(frame->uc.uc_link))) {
		BUG();
		return 1;
	}

	/* Updating the transactional state address if any */
	if (frame->uc.uc_link) {
		update_vregs(&frame->uc_transact.uc_mcontext, &rframe->uc_transact.uc_mcontext);
		frame->uc.uc_link = &rframe->uc_transact;
	}

	return 0;
}
