#include <unistd.h>

#include "asm/string.h"
#include "asm/types.h"

#include "syscall.h"
#include "parasite-vdso.h"
#include "log.h"
#include "bug.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif
#define LOG_PREFIX "vdso: "

int vdso_redirect_calls(unsigned long base_to, unsigned long base_from,
			struct vdso_symtable *to,
			struct vdso_symtable *from)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(to->symbols); i++) {
		if (vdso_symbol_empty(&from->symbols[i]))
			continue;

		pr_debug("br: %lx/%lx -> %lx/%lx (index %d)\n",
			 base_from, from->symbols[i].offset,
			 base_to, to->symbols[i].offset, i);

		write_intraprocedure_branch(base_to + to->symbols[i].offset,
					    base_from + from->symbols[i].offset);
	}

	return 0;
}
