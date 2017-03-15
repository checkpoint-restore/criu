#include "common/asm/linkage.h"

.syntax unified

ENTRY(test_and_set_bit)
	ands    ip, r1, #3
	strbne  r1, [ip]                @ assert word-aligned
	mov     r2, #1
	and     r3, r0, #31             @ Get bit offset
	mov     r0, r0, lsr #5
	add     r1, r1, r0, lsl #2      @ Get word offset
	mov     r3, r2, lsl r3          @ create mask
	dmb     ish
1:	ldrex   r2, [r1]
	ands    r0, r2, r3              @ save old value of bit
	orreq  r2, r2, r3              @ toggle bit
	strex   ip, r2, [r1]
	cmp     ip, #0
	bne     1b
	dmb     ish
	cmp     r0, #0
	movne   r0, #1
2:	bx      lr
END(test_and_set_bit)
