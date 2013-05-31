#include <sys/types.h>
#include <unistd.h>

#include "compiler.h"
#include "asm/types.h"
#include "parasite-syscall.h"
#include "asm/parasite-syscall.h"
#include "vdso.h"
#include "log.h"

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

int parasite_fixup_vdso(struct parasite_ctl *ctl, pid_t pid,
			struct vm_area_list *vma_area_list)
{
	return 0;
}
