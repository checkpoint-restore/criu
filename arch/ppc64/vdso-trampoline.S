#include "asm/linkage.h"

	.section	.text

GLOBAL(vdso_trampoline)
	mflr	12			/* r12 vdso_ptr's address */
	mtlr	0			/* restore lr */
	ld	12,0(12)		/* read value store in vdso_ptr */
	mtctr	12			/* branch to it */
	bctr
GLOBAL(vdso_trampoline_end)
