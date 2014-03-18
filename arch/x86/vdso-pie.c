#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "asm/string.h"
#include "asm/types.h"

#include "compiler.h"
#include "syscall.h"
#include "crtools.h"
#include "vdso.h"
#include "vma.h"
#include "log.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif
#define LOG_PREFIX "vdso: "

typedef struct {
	u16	movabs;
	u64	imm64;
	u16	jmp_rax;
	u32	guards;
} __packed jmp_t;

int vdso_redirect_calls(void *base_to, void *base_from,
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
			 (unsigned long)base_from, from->symbols[i].offset,
			 (unsigned long)base_to, to->symbols[i].offset, i);

		jmp.imm64 = (unsigned long)base_to + to->symbols[i].offset;
		builtin_memcpy((void *)(base_from + from->symbols[i].offset), &jmp, sizeof(jmp));
	}

	return 0;
}
