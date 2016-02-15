.globl __aeabi_uidiv

work		.req	r4	@ XXXX is this safe ?
dividend	.req	r0
divisor		.req	r1
overdone	.req	r2
result		.req	r2
curbit		.req	r3

#define	LSYM(x) x

.macro THUMB_DIV_MOD_BODY modulo
	@ Load the constant 0x10000000 into our work register.
	mov	work, #1
	lsl	work, #28
LSYM(Loop1):
	@ Unless the divisor is very big, shift it up in multiples of
	@ four bits, since this is the amount of unwinding in the main
	@ division loop.  Continue shifting until the divisor is
	@ larger than the dividend.
	cmp	divisor, work
	bhs	LSYM(Lbignum)
	cmp	divisor, dividend
	bhs	LSYM(Lbignum)
	lsl	divisor, #4
	lsl	curbit,  #4
	b	LSYM(Loop1)
LSYM(Lbignum):
	@ Set work to 0x80000000
	lsl	work, #3
LSYM(Loop2):
	@ For very big divisors, we must shift it a bit at a time, or
	@ we will be in danger of overflowing.
	cmp	divisor, work
	bhs	LSYM(Loop3)
	cmp	divisor, dividend
	bhs	LSYM(Loop3)
	lsl	divisor, #1
	lsl	curbit,  #1
	b	LSYM(Loop2)
LSYM(Loop3):
	@ Test for possible subtractions ...
  .if \modulo
	@ ... On the final pass, this may subtract too much from the dividend,
	@ so keep track of which subtractions are done, we can fix them up
	@ afterwards.
	mov	overdone, #0
	cmp	dividend, divisor
	blo	LSYM(Lover1)
	sub	dividend, dividend, divisor
LSYM(Lover1):
	lsr	work, divisor, #1
	cmp	dividend, work
	blo	LSYM(Lover2)
	sub	dividend, dividend, work
	mov	ip, curbit
	mov	work, #1
	ror	curbit, work
	orr	overdone, curbit
	mov	curbit, ip
LSYM(Lover2):
	lsr	work, divisor, #2
	cmp	dividend, work
	blo	LSYM(Lover3)
	sub	dividend, dividend, work
	mov	ip, curbit
	mov	work, #2
	ror	curbit, work
	orr	overdone, curbit
	mov	curbit, ip
LSYM(Lover3):
	lsr	work, divisor, #3
	cmp	dividend, work
	blo	LSYM(Lover4)
	sub	dividend, dividend, work
	mov	ip, curbit
	mov	work, #3
	ror	curbit, work
	orr	overdone, curbit
	mov	curbit, ip
LSYM(Lover4):
	mov	ip, curbit
  .else
	@ ... and note which bits are done in the result.  On the final pass,
	@ this may subtract too much from the dividend, but the result will be ok,
	@ since the "bit" will have been shifted out at the bottom.
	cmp	dividend, divisor
	blo	LSYM(Lover1)
	sub	dividend, dividend, divisor
	orr	result, result, curbit
LSYM(Lover1):
	lsr	work, divisor, #1
	cmp	dividend, work
	blo	LSYM(Lover2)
	sub	dividend, dividend, work
	lsr	work, curbit, #1
	orr	result, work
LSYM(Lover2):
	lsr	work, divisor, #2
	cmp	dividend, work
	blo	LSYM(Lover3)
	sub	dividend, dividend, work
	lsr	work, curbit, #2
	orr	result, work
LSYM(Lover3):
	lsr	work, divisor, #3
	cmp	dividend, work
	blo	LSYM(Lover4)
	sub	dividend, dividend, work
	lsr	work, curbit, #3
	orr	result, work
LSYM(Lover4):
  .endif

	cmp	dividend, #0			@ Early termination?
	beq	LSYM(Lover5)
	lsr	curbit,  #4			@ No, any more bits to do?
	beq	LSYM(Lover5)
	lsr	divisor, #4
	b	LSYM(Loop3)
LSYM(Lover5):
  .if \modulo
	@ Any subtractions that we should not have done will be recorded in
	@ the top three bits of "overdone".  Exactly which were not needed
	@ are governed by the position of the bit, stored in ip.
	mov	work, #0xe
	lsl	work, #28
	and	overdone, work
	beq	LSYM(Lgot_result)

	@ If we terminated early, because dividend became zero, then the
	@ bit in ip will not be in the bottom nibble, and we should not
	@ perform the additions below.  We must test for this though
	@ (rather relying upon the TSTs to prevent the additions) since
	@ the bit in ip could be in the top two bits which might then match
	@ with one of the smaller RORs.
	mov	curbit, ip
	mov	work, #0x7
	tst	curbit, work
	beq	LSYM(Lgot_result)

	mov	curbit, ip
	mov	work, #3
	ror	curbit, work
	tst	overdone, curbit
	beq	LSYM(Lover6)
	lsr	work, divisor, #3
	add	dividend, work
LSYM(Lover6):
	mov	curbit, ip
	mov	work, #2
	ror	curbit, work
	tst	overdone, curbit
	beq	LSYM(Lover7)
	lsr	work, divisor, #2
	add	dividend, work
LSYM(Lover7):
	mov	curbit, ip
	mov	work, #1
	ror	curbit, work
	tst	overdone, curbit
	beq	LSYM(Lgot_result)
	lsr	work, divisor, #1
	add	dividend, work
  .endif
LSYM(Lgot_result):
.endm


	.thumb
	.text

__aeabi_uidiv:
	mov	curbit, #1
	mov	result, #0

	push	{ work }
	cmp	dividend, divisor
	blo	LSYM(Lgot_result)

	THUMB_DIV_MOD_BODY 0

	mov	r0, result
	pop	{ work }

	bx      lr
