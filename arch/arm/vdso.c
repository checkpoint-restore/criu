#include <sys/types.h>

#include "vdso.h"
#include "log.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif
#define LOG_PREFIX "vdso: "

struct vdso_symtable vdso_sym_rt = VDSO_SYMTABLE_INIT;

int vdso_init(void)
{
	return 0;
}
