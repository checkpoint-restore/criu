#include "common/asm/linkage.h"

	.text

ENTRY(test_and_set_bit)
	and     w3, w0, #63
	eor     w0, w0, w3
	mov     x2, #1
	add     x1, x1, x0, lsr #3
	lsl     x4, x2, x3
1:	ldaxr   x2, [x1]
	lsr     x0, x2, x3
	orr  x2, x2, x4
	stlxr   w5, x2, [x1]
	cbnz    w5, 1b
	and     x0, x0, #1
3:	ret
END(test_and_set_bit)
