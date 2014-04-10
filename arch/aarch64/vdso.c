#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "parasite-syscall.h"
#include "parasite.h"
#include "compiler.h"
#include "kerndat.h"
#include "vdso.h"
#include "util.h"
#include "log.h"
#include "mem.h"
#include "vma.h"

#include "asm/types.h"
#include "asm/parasite-syscall.h"


#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif
#define LOG_PREFIX "vdso: "


int parasite_fixup_vdso(struct parasite_ctl *ctl, pid_t pid,
			struct vm_area_list *vma_area_list)
{
	return 0;
}
