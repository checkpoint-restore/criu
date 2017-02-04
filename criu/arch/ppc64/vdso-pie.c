#include <unistd.h>
#include <string.h>

#include "asm/types.h"

#include "syscall.h"
#include "parasite-vdso.h"
#include "log.h"
#include "common/bug.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif
#define LOG_PREFIX "vdso: "

/* This symbols are defined in vdso-trampoline.S */
extern char *vdso_trampoline, *vdso_trampoline_end;

static inline void invalidate_caches(unsigned long at)
{
    asm volatile("isync		\n"	\
		 "li 	3,0	\n" 	\
		 "dcbf	3,%0	\n"	\
		 "sync		\n"	\
		 "icbi 	3,%0	\n" 	\
		 "isync		\n" 	\
		 : /* no output */	\
		 : "r"(at)		\
		 :"memory", "r3");
}

/* This is the size of the trampoline call :
 * 	mlfr	r0
 *	bl	trampoline
 *	<64 bit address>
 */
#define TRAMP_CALL_SIZE	(2*sizeof(uint32_t) + sizeof(uint64_t))

/*
 * put_trampoline does 2 things :
 *
 *   1. it looks for a place in the checkpointed vDSO where to put the
 *	trampoline code (see vdso-trampoline.S).
 *
 *   2. for each symbol from the checkpointed vDSO, it checks that there are
 *	enough place to put the call to the vDSO trampoline (see
 *	TRAMP_CALL_SIZE's comment above).
 *	This done by checking that there is no interesting symbols in the range
 *	of current one's offset -> (current one's offset + TRAMP_CALL_SIZE).
 *	Unfortunately the symbols are not sorted by address so we have to look
 *	for the complete table all the time. Since the vDSO is small, this is
 *	not a big issue.
 */
static unsigned long put_trampoline(unsigned long at, struct vdso_symtable *sym)
{
	int i,j;
	unsigned long size;
	unsigned long trampoline = 0;

	/* First of all we have to find a place where to put the trampoline
	 * code.
	 */
	size = (unsigned long)&vdso_trampoline_end
		- (unsigned long)&vdso_trampoline;

	for (i = 0; i < ARRAY_SIZE(sym->symbols); i++) {
		if (vdso_symbol_empty(&sym->symbols[i]))
			continue;

		pr_debug("Checking '%s' at %lx\n", sym->symbols[i].name,
			 sym->symbols[i].offset);

		/* find the nearest followin symbol we are interested in */
		for (j=0; j < ARRAY_SIZE(sym->symbols); j++) {
			if (i==j || vdso_symbol_empty(&sym->symbols[j]))
				continue;

			if (sym->symbols[j].offset <= sym->symbols[i].offset)
				/* this symbol is above the current one */
				continue;

			if ((sym->symbols[i].offset+TRAMP_CALL_SIZE) >
			    sym->symbols[j].offset) {
				/* we have a major issue here since we cannot
				 * even put the trampoline call for this symbol
				 */
				pr_err("Can't handle small vDSO symbol %s\n",
				       sym->symbols[i].name);
				return 0;
			}

			if (trampoline)
				/* no need to put it twice */
				continue;

			if ((sym->symbols[j].offset -
			     (sym->symbols[i].offset+TRAMP_CALL_SIZE)) <= size)
				/* not enough place */
				continue;

			/* We can put the trampoline there */
			trampoline = at + sym->symbols[i].offset;
			trampoline += TRAMP_CALL_SIZE;

			pr_debug("Putting vDSO trampoline in %s at %lx\n",
				 sym->symbols[i].name, trampoline);
			memcpy((void *)trampoline, &vdso_trampoline,
				       size);
			invalidate_caches(trampoline);
		}
	}

	return trampoline;
}

static inline void put_trampoline_call(unsigned long at, unsigned long to,
				       unsigned long tr)
{
    uint32_t *addr = (uint32_t *)at;;

    *addr++ = 0x7C0802a6;					/* mflr	r0 */
    *addr++ = 0x48000001 | ((long)(tr-at-4) & 0x3fffffc);	/* bl tr */
    *(uint64_t *)addr = to;	/* the address to read by the trampoline */

    invalidate_caches(at);
}

int vdso_redirect_calls(unsigned long base_to,
			unsigned long base_from,
			struct vdso_symtable *to,
			struct vdso_symtable *from)
{
	unsigned int i;
	unsigned long trampoline;

	trampoline = (unsigned long)put_trampoline(base_from, from);
	if (!trampoline)
		return 1;

	for (i = 0; i < ARRAY_SIZE(to->symbols); i++) {
		if (vdso_symbol_empty(&from->symbols[i]))
			continue;

		pr_debug("br: %lx/%lx -> %lx/%lx (index %d) '%s'\n",
			 base_from, from->symbols[i].offset,
			 base_to, to->symbols[i].offset, i,
			 from->symbols[i].name);

		put_trampoline_call(base_from + from->symbols[i].offset,
				    base_to + to->symbols[i].offset,
				    trampoline);
	}

	return 0;
}
