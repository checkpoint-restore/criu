#include <unistd.h>

#include "asm/types.h"

#include <compel/plugins/std/string.h>
#include <compel/plugins/std/syscall.h>
#include "parasite-vdso.h"
#include "log.h"
#include "common/bug.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif
#define LOG_PREFIX "vdso: "

static void insert_trampoline(uintptr_t from, uintptr_t to)
{
	struct {
		uint32_t	ldr_pc;
		uint32_t	imm32;
		uint32_t	guards;
	} __packed jmp = {
		.ldr_pc		= 0xe51ff004,		/* ldr	pc, [pc, #-4] */
		.imm32		= to,
		.guards		= 0xe1200070,		/* bkpt	0x0000 */
	};
	void *iflush_start	= (void *)from;
	void *iflush_end	= iflush_start + sizeof(jmp);

	memcpy((void *)from, &jmp, sizeof(jmp));

	__builtin___clear_cache(iflush_start, iflush_end);
}

int vdso_redirect_calls(unsigned long base_to, unsigned long base_from,
			struct vdso_symtable *sto, struct vdso_symtable *sfrom,
			bool compat_vdso)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(sto->symbols); i++) {
		uintptr_t from, to;

		if (vdso_symbol_empty(&sfrom->symbols[i]))
			continue;

		pr_debug("jmp: %lx/%lx -> %lx/%lx (index %d)\n",
			 base_from, sfrom->symbols[i].offset,
			 base_to, sto->symbols[i].offset, i);

		from = base_from + sfrom->symbols[i].offset;
		to = base_to + sto->symbols[i].offset;

		insert_trampoline(from, to);
	}

	return 0;
}
