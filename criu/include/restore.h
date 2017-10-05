#ifndef __CR_INC_RESTORE_H__
#define __CR_INC_RESTORE_H__

#include "pid.h"
#include "types.h"
#include "asm/restore.h"

extern int arch_set_thread_regs_nosigrt(struct pid *pid);

#endif
