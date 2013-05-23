#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "asm/types.h"

#include "compiler.h"
#include "crtools.h"
#include "kerndat.h"
#include "vdso.h"
#include "log.h"
#include "mem.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif
#define LOG_PREFIX "vdso: "

struct vdso_symtable vdso_sym_rt = VDSO_SYMTABLE_INIT;

static int vdso_fill_self_symtable(struct vdso_symtable *s)
{
	char buf[512];
	int ret = -1;
	FILE *maps;

	VDSO_INIT_SYMTABLE(s);

	maps = fopen("/proc/self/maps", "r");
	if (!maps) {
		pr_perror("Can't open self-vma");
		return -1;
	}

	while (fgets(buf, sizeof(buf), maps)) {
		unsigned long start, end;

		if (strstr(buf, "[vdso]") == NULL)
			continue;

		ret = sscanf(buf, "%lx-%lx", &start, &end);
		if (ret != 2) {
			ret = -1;
			pr_err("Can't find vDSO bounds\n");
			break;
		}

		s->vma_start = start;
		s->vma_end = end;

		ret = vdso_fill_symtable((void *)start, end - start, s);
		break;
	}

	fclose(maps);
	return ret;
}

int vdso_init(void)
{
	if (vdso_fill_self_symtable(&vdso_sym_rt))
		return -1;
	return 0;
}
