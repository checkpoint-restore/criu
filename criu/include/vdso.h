#ifndef __CR_VDSO_H__
#define __CR_VDSO_H__

#include <sys/mman.h>
#include <stdbool.h>

#include "config.h"

#ifdef CONFIG_VDSO

#include "util-vdso.h"

extern struct vdso_symtable vdso_sym_rt;

extern int vdso_init(void);

extern int parasite_fixup_vdso(struct parasite_ctl *ctl, pid_t pid,
			       struct vm_area_list *vma_area_list);

#else /* CONFIG_VDSO */

#define vdso_init()						(0)
#define parasite_fixup_vdso(ctl, pid, vma_area_list)		(0)

#endif /* CONFIG_VDSO */

#endif /* __CR_VDSO_H__ */
