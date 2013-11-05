#include <sys/types.h>

#include "vdso.h"
#include "vma.h"
#include "log.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif
#define LOG_PREFIX "vdso: "

int vdso_redirect_calls(void *base_to, void *base_from,
			struct vdso_symtable *to,
			struct vdso_symtable *from)
{
	return 0;
}

int vdso_fill_symtable(char *mem, size_t size, struct vdso_symtable *t)
{
	return 0;
}

int vdso_remap(char *who, unsigned long from, unsigned long to, size_t size)
{
	return 0;
}

int vdso_proxify(char *who, struct vdso_symtable *sym_rt, VmaEntry *vma, unsigned long vdso_rt_parked_at)
{
	return 0;
}
