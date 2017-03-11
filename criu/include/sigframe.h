/*
 * Generic sigframe bits.
 */

#ifndef __CR_SIGFRAME_H__
#define __CR_SIGFRAME_H__

#include <compel/asm/sigframe.h>
#include "images/core.pb-c.h"

extern int construct_sigframe(struct rt_sigframe *sigframe,
			      struct rt_sigframe *rsigframe,
			      k_rtsigset_t *blkset,
			      CoreEntry *core);

#endif /* __CR_SIGFRAME_H__ */
