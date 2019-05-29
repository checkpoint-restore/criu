/*
 * Code borrowed from gcc, arm/lib1funcs.S
 * and adapted to CRIU macros.
 */

#if defined(__thumb__)
/*
 * We don't support compiling PIEs in Thumb mode,
 * see top Makefile for details (ARM CFLAGS_PIE section).
*/
#error Unsupported Thumb mode
#endif

#include "common/asm/linkage.h"

#define RET	bx	lr
#define RETc(x)	bx##x	lr
#define LSYM(x) .x

.macro do_it cond, suffix=""
.endm

.macro ARM_DIV2_ORDER divisor, order
	clz	\order, \divisor
	rsb	\order, \order, #31
.endm

.macro ARM_DIV_BODY dividend, divisor, result, curbit
	clz	\curbit, \dividend
	clz	\result, \divisor
	sub	\curbit, \result, \curbit
	rsbs	\curbit, \curbit, #31
	addne	\curbit, \curbit, \curbit, lsl #1
	mov	\result, #0
	addne	pc, pc, \curbit, lsl #2
	nop
	.set	shift, 32
	.rept	32
	.set	shift, shift - 1
	cmp	\dividend, \divisor, lsl #shift
	adc	\result, \result, \result
	subcs	\dividend, \dividend, \divisor, lsl #shift
	.endr
.endm

/*
 * XXX: as an optimization add udiv instruction based version.
 * It's possible to check if CPU supports the instruction by
 * reading Instruction Set Attribute Register (ID_ISAR0)
 * and checking fields "Divide_instrs".
 */
ENTRY(__aeabi_uidiv)
	/* Note: if called via udivsi3_skip_div0_test, this will unnecessarily
	   check for division-by-zero a second time.  */
LSYM(udivsi3_skip_div0_test):
	subs	r2, r1, #1
	do_it	eq
	RETc(eq)
	bcc	LSYM(Ldiv0)
	cmp	r0, r1
	bls	11f
	tst	r1, r2
	beq	12f

	ARM_DIV_BODY r0, r1, r2, r3

	mov	r0, r2
	RET

11:	do_it	eq, e
	moveq	r0, #1
	movne	r0, #0
	RET

12:	ARM_DIV2_ORDER r1, r2

	mov	r0, r0, lsr r2
	RET

LSYM(Ldiv0):
	.byte   0xf0, 0x01, 0xf0, 0xe7		@ the instruction UDF #32 generates the signal SIGTRAP in Linux

END(__aeabi_uidiv)
ALIAS(__udivsi3, __aeabi_uidiv)

ENTRY(__aeabi_uidivmod)
	cmp	r1, #0
	beq	LSYM(Ldiv0)
	stmfd	sp!, { r0, r1, lr }
	bl	LSYM(udivsi3_skip_div0_test)
	ldmfd	sp!, { r1, r2, lr }
	mul	r3, r2, r0
	sub	r1, r1, r3
	RET
END(__aeabi_uidivmod)
ALIAS(__umodsi3, __aeabi_uidiv)
