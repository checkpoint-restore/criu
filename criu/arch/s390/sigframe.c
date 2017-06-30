#include <stdlib.h>
#include <stdint.h>

#include "asm/sigframe.h"
#include "asm/types.h"

#include "log.h"

/*
 * Nothing to do since we don't have any pointers to adjust
 * in the signal frame.
 *
 * - sigframe : Pointer to local signal frame
 * - rsigframe: Pointer to remote signal frame of inferior
 */
int sigreturn_prep_fpu_frame(struct rt_sigframe *sigframe,
			     struct rt_sigframe *rsigframe)
{
	return 0;
}
