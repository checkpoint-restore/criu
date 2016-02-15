/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) IBM Corporation, 2012
 *
 * Author: Anton Blanchard <anton@au.ibm.com>
 *
 * --
 * Copied from the kernel file arch/powerpc/lib/memcpy_power7.S
 * Altivec support has been removed so we don't taint restored process.
 */
#include "asm/linkage.h"

/*
 * When building the parasite code, the compiler may rely on the C library
 * service memcpy to initialise big local variable in the stack.
 */
ENTRY(memcpy)
ENTRY(memcpy_power7)
	cmpldi	r5,16
	std	r3,-STACKFRAMESIZE+STK_REG(R31)(r1)
	blt	.Lshort_copy

.Lnonvmx_copy:
	/* Get the source 8B aligned */
	neg	r6,r4
	mtocrf	0x01,r6
	clrldi	r6,r6,(64-3)

	bf	cr7*4+3,1f
	lbz	r0,0(r4)
	addi	r4,r4,1
	stb	r0,0(r3)
	addi	r3,r3,1

1:	bf	cr7*4+2,2f
	lhz	r0,0(r4)
	addi	r4,r4,2
	sth	r0,0(r3)
	addi	r3,r3,2

2:	bf	cr7*4+1,3f
	lwz	r0,0(r4)
	addi	r4,r4,4
	stw	r0,0(r3)
	addi	r3,r3,4

3:	sub	r5,r5,r6
	cmpldi	r5,128
	blt	5f

	mflr	r0
	stdu	r1,-STACKFRAMESIZE(r1)
	std	r14,STK_REG(R14)(r1)
	std	r15,STK_REG(R15)(r1)
	std	r16,STK_REG(R16)(r1)
	std	r17,STK_REG(R17)(r1)
	std	r18,STK_REG(R18)(r1)
	std	r19,STK_REG(R19)(r1)
	std	r20,STK_REG(R20)(r1)
	std	r21,STK_REG(R21)(r1)
	std	r22,STK_REG(R22)(r1)
	std	r0,STACKFRAMESIZE+16(r1)

	srdi	r6,r5,7
	mtctr	r6

	/* Now do cacheline (128B) sized loads and stores. */
	.align	5
4:
	ld	r0,0(r4)
	ld	r6,8(r4)
	ld	r7,16(r4)
	ld	r8,24(r4)
	ld	r9,32(r4)
	ld	r10,40(r4)
	ld	r11,48(r4)
	ld	r12,56(r4)
	ld	r14,64(r4)
	ld	r15,72(r4)
	ld	r16,80(r4)
	ld	r17,88(r4)
	ld	r18,96(r4)
	ld	r19,104(r4)
	ld	r20,112(r4)
	ld	r21,120(r4)
	addi	r4,r4,128
	std	r0,0(r3)
	std	r6,8(r3)
	std	r7,16(r3)
	std	r8,24(r3)
	std	r9,32(r3)
	std	r10,40(r3)
	std	r11,48(r3)
	std	r12,56(r3)
	std	r14,64(r3)
	std	r15,72(r3)
	std	r16,80(r3)
	std	r17,88(r3)
	std	r18,96(r3)
	std	r19,104(r3)
	std	r20,112(r3)
	std	r21,120(r3)
	addi	r3,r3,128
	bdnz	4b

	clrldi	r5,r5,(64-7)

	ld	r14,STK_REG(R14)(r1)
	ld	r15,STK_REG(R15)(r1)
	ld	r16,STK_REG(R16)(r1)
	ld	r17,STK_REG(R17)(r1)
	ld	r18,STK_REG(R18)(r1)
	ld	r19,STK_REG(R19)(r1)
	ld	r20,STK_REG(R20)(r1)
	ld	r21,STK_REG(R21)(r1)
	ld	r22,STK_REG(R22)(r1)
	addi	r1,r1,STACKFRAMESIZE

	/* Up to 127B to go */
5:	srdi	r6,r5,4
	mtocrf	0x01,r6

6:	bf	cr7*4+1,7f
	ld	r0,0(r4)
	ld	r6,8(r4)
	ld	r7,16(r4)
	ld	r8,24(r4)
	ld	r9,32(r4)
	ld	r10,40(r4)
	ld	r11,48(r4)
	ld	r12,56(r4)
	addi	r4,r4,64
	std	r0,0(r3)
	std	r6,8(r3)
	std	r7,16(r3)
	std	r8,24(r3)
	std	r9,32(r3)
	std	r10,40(r3)
	std	r11,48(r3)
	std	r12,56(r3)
	addi	r3,r3,64

	/* Up to 63B to go */
7:	bf	cr7*4+2,8f
	ld	r0,0(r4)
	ld	r6,8(r4)
	ld	r7,16(r4)
	ld	r8,24(r4)
	addi	r4,r4,32
	std	r0,0(r3)
	std	r6,8(r3)
	std	r7,16(r3)
	std	r8,24(r3)
	addi	r3,r3,32

	/* Up to 31B to go */
8:	bf	cr7*4+3,9f
	ld	r0,0(r4)
	ld	r6,8(r4)
	addi	r4,r4,16
	std	r0,0(r3)
	std	r6,8(r3)
	addi	r3,r3,16

9:	clrldi	r5,r5,(64-4)

	/* Up to 15B to go */
.Lshort_copy:
	mtocrf	0x01,r5
	bf	cr7*4+0,12f
	lwz	r0,0(r4)	/* Less chance of a reject with word ops */
	lwz	r6,4(r4)
	addi	r4,r4,8
	stw	r0,0(r3)
	stw	r6,4(r3)
	addi	r3,r3,8

12:	bf	cr7*4+1,13f
	lwz	r0,0(r4)
	addi	r4,r4,4
	stw	r0,0(r3)
	addi	r3,r3,4

13:	bf	cr7*4+2,14f
	lhz	r0,0(r4)
	addi	r4,r4,2
	sth	r0,0(r3)
	addi	r3,r3,2

14:	bf	cr7*4+3,15f
	lbz	r0,0(r4)
	stb	r0,0(r3)

15:	ld	r3,-STACKFRAMESIZE+STK_REG(R31)(r1)
	blr

.Lunwind_stack_nonvmx_copy:
	addi	r1,r1,STACKFRAMESIZE
	b	.Lnonvmx_copy

