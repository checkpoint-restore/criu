.global write_intraprocedure_branch

/* to is x0, from is x1 */
write_intraprocedure_branch:
	/* load two 32-bit instructions */
	ldr x2, loadbranch
	/* store 64 bits of instructions and 64 bits of destination address */
	stp x2, x0, [x1]
	/* perform required cache maintenance and synronization operations */
	dc cvau, x1
	dsb ish
	ic ivau, x1
	dsb ish
	isb
	ret

/* intraprocedure trampoline instructions */
loadbranch:
	ldr x16, =destination
	br x16
/* label to get relative position of literal pool */
destination:
