#include <unistd.h>

#include "restorer.h"
#include "asm/restore.h"
#include "asm/restorer.h"

#include "protobuf/core.pb-c.h"

int construct_sigframe(struct rt_sigframe *sigframe,
				     struct rt_sigframe *rsigframe,
				     CoreEntry *core)
{
	k_rtsigset_t *blk_sigset = &RT_SIGFRAME_UC(sigframe).uc_sigmask;

	if (core->tc)
		memcpy(blk_sigset, &core->tc->blk_sigset, sizeof(k_rtsigset_t));
	else if (core->thread_core->has_blk_sigset) {
		memcpy(blk_sigset,
			&core->thread_core->blk_sigset, sizeof(k_rtsigset_t));
	} else
		memset(blk_sigset, 0, sizeof(k_rtsigset_t));

	sigframe->fpu_state.has_fpu = true;
	if (restore_fpu(sigframe, core))
		return -1;

	if (sigframe->fpu_state.has_fpu)
		if (sigreturn_prep_fpu_frame(sigframe, &rsigframe->fpu_state))
			return -1;

	if (restore_gpregs(sigframe, CORE_THREAD_ARCH_INFO(core)->gpregs))
		return -1;

	return 0;
}
