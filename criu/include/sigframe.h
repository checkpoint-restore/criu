/*
 * Generic sigframe bits.
 */

#ifndef __CR_SIGFRAME_H__
#define __CR_SIGFRAME_H__

#include "images/core.pb-c.h"
#include <compel/asm/sigframe.h>

extern int construct_sigframe(struct rt_sigframe *sigframe, struct rt_sigframe *rsigframe, k_rtsigset_t *blkset,
			      CoreEntry *core);

#endif /* __CR_SIGFRAME_H__ */
