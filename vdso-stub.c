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


int vdso_init(void)
{
	return 0;
}
