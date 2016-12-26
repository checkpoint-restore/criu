#ifndef __CR_ASM_BITOPS_H__
#define __CR_ASM_BITOPS_H__

#include "common/compiler.h"
#include "common/asm-generic/bitops.h"

extern int test_and_set_bit(int nr, volatile unsigned long *p);

#endif /* __CR_ASM_BITOPS_H__ */
