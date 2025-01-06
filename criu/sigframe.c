#include <unistd.h>
#include <string.h>
#include "log.h"
#include "restore.h"
#include "images/core.pb-c.h"

#ifndef setup_sas
static inline void setup_sas(struct rt_sigframe *sigframe, ThreadSasEntry *sas)
{
	if (sas) {
#define UC RT_SIGFRAME_UC(sigframe)

		UC->uc_stack.ss_sp = (void *)decode_pointer((sas)->ss_sp);
		UC->uc_stack.ss_flags = (int)(sas)->ss_flags;
		UC->uc_stack.ss_size = (size_t)(sas)->ss_size;
#undef UC
	}
}
#endif

int construct_sigframe(struct rt_sigframe *sigframe, struct rt_sigframe *rsigframe, k_rtsigset_t *blkset,
		       CoreEntry *core)
{
	/*
	 * Copy basic register set in the first place: this will set
	 * rt_sigframe type: native/compat.
	 */
	if (restore_gpregs(sigframe, CORE_THREAD_ARCH_INFO(core)->gpregs))
		return -1;

	if (blkset)
		rt_sigframe_copy_sigset(sigframe, blkset);
	else
		rt_sigframe_erase_sigset(sigframe);

	if (restore_fpu(sigframe, core))
		return -1;

	if (RT_SIGFRAME_HAS_FPU(sigframe))
		if (sigreturn_prep_fpu_frame(sigframe, rsigframe))
			return -1;

	setup_sas(sigframe, core->thread_core->sas);

	return 0;
}
