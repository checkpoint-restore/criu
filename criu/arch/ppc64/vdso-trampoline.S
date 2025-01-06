#include "common/asm/linkage.h"

	.section	.text

GLOBAL(vdso_trampoline)
	mflr	r12			/* r12 vdso_ptr's address */
	mtlr	r0			/* restore lr */
	ld	r12,0(r12)		/* read value store in vdso_ptr */
	mtctr	r12			/* branch to it */
	bctr
GLOBAL(vdso_trampoline_end)
