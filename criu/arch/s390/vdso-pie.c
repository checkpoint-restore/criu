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

/*
 * Trampoline instruction sequence
 */
typedef struct {
	u8 larl[6]; /* Load relative address of imm64 */
	u8 lg[6];   /* Load %r1 with imm64 */
	u8 br[2];   /* Branch to %r1 */
	u64 addr;   /* Jump address */
	u32 guards; /* Guard bytes */
} __packed jmp_t;

/*
 * Trampoline template: Use %r1 to jump
 */
jmp_t jmp = {
	/* larl %r1,e (addr) */
	.larl = { 0xc0, 0x10, 0x00, 0x00, 0x00, 0x07 },
	/* lg   %r1,0(%r1) */
	.lg = { 0xe3, 0x10, 0x10, 0x00, 0x00, 0x04 },
	/* br   %r1 */
	.br = { 0x07, 0xf1 },
	.guards = 0xcccccccc,
};

/*
 * Insert trampoline code into old vdso entry points to
 * jump to new vdso functions.
 */
int vdso_redirect_calls(unsigned long base_to, unsigned long base_from, struct vdso_symtable *to,
			struct vdso_symtable *from, bool __always_unused compat_vdso)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(to->symbols); i++) {
		if (vdso_symbol_empty(&from->symbols[i]))
			continue;

		pr_debug("jmp: %s: %lx/%lx -> %lx/%lx (index %d)\n", from->symbols[i].name, base_from,
			 from->symbols[i].offset, base_to, to->symbols[i].offset, i);

		jmp.addr = base_to + to->symbols[i].offset;
		memcpy((void *)(base_from + from->symbols[i].offset), &jmp, sizeof(jmp));
	}

	return 0;
}
