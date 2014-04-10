#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "asm/string.h"
#include "asm/types.h"

#include "compiler.h"
#include "syscall.h"
#include "crtools.h"
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
	pr_err("vDSO proxy isn't implemented yet");
	return -1;
}
