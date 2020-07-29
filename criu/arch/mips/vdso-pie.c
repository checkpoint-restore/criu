#include <unistd.h>
#include "asm/types.h"

#include "flog.h"
#include <compel/plugins/std/string.h>
#include <compel/plugins/std/syscall.h>
#include "parasite-vdso.h"
#include "log.h"
#include "common/bug.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif
#define LOG_PREFIX "vdso: "

int vdso_redirect_calls(unsigned long base_to, unsigned long base_from,
			struct vdso_symtable *sto, struct vdso_symtable *sfrom,
			bool compat_vdso)
{
    pr_err("Vdso proxification isn't implemented on mips\n");
    return -1;
}
