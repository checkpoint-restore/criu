#ifndef __CR_INC_RESTORE_H__
#define __CR_INC_RESTORE_H__

#include "asm/restore.h"
#include "pid.h"
#include "types.h"

extern int arch_set_thread_regs_nosigrt(struct pid *pid);

#endif
