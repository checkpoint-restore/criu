#include <unistd.h>
#include "asm/types.h"

#include <compel/plugins/std/string.h>
#include <compel/plugins/std/syscall.h>
#include "parasite-vdso.h"
#include "log.h"
#include "common/bug.h"

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "vdso: "
static void insert_trampoline(uintptr_t from, uintptr_t to)
{
	struct {
		uint32_t pcaddi;
		uint32_t ldptr;
		uint32_t jirl;
		uint32_t guards;
		uint64_t imm64;
	} __packed jmp = {
		.pcaddi = 0x18000095, /*  pcaddi  $x, 4        */
		.ldptr = 0x260002b5,  /*  ldptr.d $x, $x, 0    */
		.jirl = 0x4c0002a0,   /*  jirl    $zero, $x, 0 */
		.guards = 0x002a0000, /*  break   0            */
		.imm64 = to,
	};
	memcpy((void *)from, &jmp, sizeof(jmp));
}

int vdso_redirect_calls(unsigned long base_to, unsigned long base_from, struct vdso_symtable *sto,
			struct vdso_symtable *sfrom, bool compat_vdso)
{
	unsigned int i;
	unsigned long from, to;
	for (i = 0; i < ARRAY_SIZE(sto->symbols); i++) {
		if (vdso_symbol_empty(&sfrom->symbols[i]))
			continue;
		pr_debug("br: %lx/%lx -> %lx/%lx (index %d)\n", base_from, sfrom->symbols[i].offset, base_to,
			 sto->symbols[i].offset, i);

		from = base_from + sfrom->symbols[i].offset;
		to = base_to + sto->symbols[i].offset;
		insert_trampoline(from, to);
	}
	return 0;
}
