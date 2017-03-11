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

#ifdef CONFIG_X86_64
typedef struct {
	u16	movabs;
	u64	imm64;
	u16	jmp_rax;
	u32	guards;
} __packed jmp_t;
#define IMMEDIATE(j)	(j.imm64)

jmp_t jmp = {
	.movabs		= 0xb848,
	.jmp_rax	= 0xe0ff,
	.guards		= 0xcccccccc,
};

#else /* CONFIG_X86_64 */
typedef struct {
	u8	movl;
	u32	imm32;
	u16	jmp_eax;
	u32	guards;
} __packed jmp_t;
#define IMMEDIATE(j)	(j.imm32)

jmp_t jmp = {
	.movl		= 0xb8,
	.jmp_eax	= 0xe0ff,
	.guards		= 0xcccccccc,
};
#endif /* CONFIG_X86_64 */

int vdso_redirect_calls(unsigned long base_to, unsigned long base_from,
			struct vdso_symtable *to,
			struct vdso_symtable *from)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(to->symbols); i++) {
		if (vdso_symbol_empty(&from->symbols[i]))
			continue;

		pr_debug("jmp: %lx/%lx -> %lx/%lx (index %d)\n",
			 base_from, from->symbols[i].offset,
			 base_to, to->symbols[i].offset, i);

		IMMEDIATE(jmp) = base_to + to->symbols[i].offset;
		memcpy((void *)(base_from + from->symbols[i].offset), &jmp, sizeof(jmp));
	}

	return 0;
}
