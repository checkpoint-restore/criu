#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "vdso.h"
#include "log.h"
#include "util.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif
#define LOG_PREFIX "vdso: "


struct vdso_symtable vdso_sym_rt = VDSO_SYMTABLE_INIT;
u64 vdso_pfn = VDSO_BAD_PFN;

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

	return vaddr_to_pfn(vdso_sym_rt.vma_start, &vdso_pfn);
}

