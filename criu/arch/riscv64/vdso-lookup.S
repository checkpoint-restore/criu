#include "common/asm/linkage.h"

.section	.text

/* Expects t0 to hold the index into the lookup table. */
GLOBAL(riscv_vdso_lookup)
	/* Get the beginning of the lookup table */
	la t1, riscv_vdso_lookup_end
	/* Scale the index */
	slli t0, t0, 3
	add t1, t0, t1
	ld t2, 0(t1)
	jr t2

GLOBAL(riscv_vdso_lookup_end)