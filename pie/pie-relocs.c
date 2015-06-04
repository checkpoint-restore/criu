#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#include <fcntl.h>
#include <elf.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "asm-generic/int.h"

#include "compiler.h"
#include "piegen/uapi/types.h"
#include "bug.h"

__maybe_unused void elf_relocs_apply(void *mem, void *vbase, size_t size, elf_reloc_t *elf_relocs, size_t nr_relocs)
{
	size_t i, j;

	for (i = 0, j = 0; i < nr_relocs; i++) {
		if (elf_relocs[i].type & PIEGEN_TYPE_LONG) {
			long *where = mem + elf_relocs[i].offset;
			long *p = mem + size;

			if (elf_relocs[i].type & PIEGEN_TYPE_GOTPCREL) {
				int *value = (int *)where;
				int rel;

				p[j] = (long)vbase + elf_relocs[i].value;
				rel = (unsigned)((void *)&p[j] - (void *)mem) - elf_relocs[i].offset + elf_relocs[i].addend;

				*value = rel;
				j++;
			} else
				*where = elf_relocs[i].value + elf_relocs[i].addend + (unsigned long)vbase;
		} else if (elf_relocs[i].type & PIEGEN_TYPE_INT) {
			int *where = (mem + elf_relocs[i].offset);
			*where = elf_relocs[i].value + elf_relocs[i].addend + (unsigned long)vbase;
		} else
			BUG();
	}
}
