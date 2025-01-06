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

static void insert_trampoline32(uintptr_t from, uintptr_t to)
{
	struct {
		u8 movl;
		u32 imm32;
		u16 jmp_eax;
		u32 guards;
	} __packed jmp = {
		.movl = 0xb8,
		.imm32 = (uint32_t)to,
		.jmp_eax = 0xe0ff,
		.guards = 0xcccccccc,
	};

	memcpy((void *)from, &jmp, sizeof(jmp));
}

static void insert_trampoline64(uintptr_t from, uintptr_t to)
{
	struct {
		u16 movabs;
		u64 imm64;
		u16 jmp_rax;
		u32 guards;
	} __packed jmp = {
		.movabs = 0xb848,
		.imm64 = to,
		.jmp_rax = 0xe0ff,
		.guards = 0xcccccccc,
	};

	memcpy((void *)from, &jmp, sizeof(jmp));
}

int vdso_redirect_calls(unsigned long base_to, unsigned long base_from, struct vdso_symtable *sto,
			struct vdso_symtable *sfrom, bool compat_vdso)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(sto->symbols); i++) {
		uintptr_t from, to;

		if (vdso_symbol_empty(&sfrom->symbols[i]))
			continue;

		pr_debug("jmp: %lx/%lx -> %lx/%lx (index %d)\n", base_from, sfrom->symbols[i].offset, base_to,
			 sto->symbols[i].offset, i);

		from = base_from + sfrom->symbols[i].offset;
		to = base_to + sto->symbols[i].offset;

		if (!compat_vdso)
			insert_trampoline64(from, to);
		else
			insert_trampoline32(from, to);
	}

	return 0;
}
