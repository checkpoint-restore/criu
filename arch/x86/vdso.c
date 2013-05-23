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
#include "util.h"
#include "log.h"
#include "mem.h"

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
	int ret = -1, fd;
	off_t off;

	if (vdso_fill_self_symtable(&vdso_sym_rt))
		return -1;

	fd = open_proc(getpid(), "pagemap");
	if (fd < 0)
		return -1;

	off = (vdso_sym_rt.vma_start / PAGE_SIZE) * sizeof(u64);
	if (lseek(fd, off, SEEK_SET) != off) {
		pr_perror("Failed to seek address %lx\n", vdso_sym_rt.vma_start);
		goto out;
	}

	ret = read(fd, &vdso_pfn, sizeof(vdso_pfn));
	if (ret < 0 || ret != sizeof(vdso_pfn)) {
		pr_perror("Can't read pme for pid %d", getpid());
		ret = -1;
	} else {
		vdso_pfn = PME_PFRAME(vdso_pfn);
		ret = 0;
	}
out:
	close(fd);
	return ret;
}
