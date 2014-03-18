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
