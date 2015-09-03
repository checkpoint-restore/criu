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

#ifdef CONFIG_X86_64
typedef struct {
	u16	movabs;
	u64	imm64;
	u16	jmp_rax;
	u32	guards;
} __packed jmp_t;

int vdso_redirect_calls(unsigned long base_to, unsigned long base_from,
			struct vdso_symtable *to,
			struct vdso_symtable *from)
{
	jmp_t jmp = {
		.movabs		= 0xb848,
		.jmp_rax	= 0xe0ff,
		.guards		= 0xcccccccc,
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(to->symbols); i++) {
		if (vdso_symbol_empty(&from->symbols[i]))
			continue;

		pr_debug("jmp: %lx/%lx -> %lx/%lx (index %d)\n",
			 base_from, from->symbols[i].offset,
			 base_to, to->symbols[i].offset, i);

		jmp.imm64 = base_to + to->symbols[i].offset;
		builtin_memcpy((void *)(base_from + from->symbols[i].offset), &jmp, sizeof(jmp));
	}

	return 0;
}

#else /* CONFIG_X86_64 */

int vdso_redirect_calls(unsigned long base_to, unsigned long  base_from,
			struct vdso_symtable *to,
			struct vdso_symtable *from)
{
	return 0;
}

#endif /* CONFIG_X86_64 */
