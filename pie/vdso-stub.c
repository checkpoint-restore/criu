#include <elf.h>

#include <sys/mman.h>

#include "compiler.h"
#include "vdso.h"
#include "syscall.h"
#include "log.h"

#include "asm/string.h"


#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif
#define LOG_PREFIX "vdso: "

int vdso_remap(char *who, unsigned long from, unsigned long to, size_t size)
{
	return 0;
}

int vdso_fill_symtable(char *mem, size_t size, struct vdso_symtable *t)
{
	return 0;
}

int vdso_proxify(char *who, struct vdso_symtable *sym_rt, VmaEntry *vma, unsigned long vdso_rt_parked_at)
{
	return 0;
}
