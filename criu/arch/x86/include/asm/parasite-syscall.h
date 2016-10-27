#ifndef __CR_ASM_PARASITE_SYSCALL_H__
#define __CR_ASM_PARASITE_SYSCALL_H__

#include "asm/types.h"

struct parasite_ctl;

/*
 * For x86_32 __NR_mmap inside the kernel represents old_mmap system
 * call, but since we didn't use it yet lets go further and simply
 * define own alias for __NR_mmap2 which would allow us to unify code
 * between 32 and 64 bits version.
 */
#define __NR32_mmap __NR32_mmap2


#endif
