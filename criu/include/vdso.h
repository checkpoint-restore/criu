#ifndef __CR_VDSO_H__
#define __CR_VDSO_H__

#include <sys/mman.h>
#include <stdbool.h>

#include "config.h"

#ifdef CONFIG_VDSO

#include "util-vdso.h"

extern struct vdso_maps vdso_maps;
extern struct vdso_maps vdso_maps_compat;

extern int vdso_init_dump(void);
extern int vdso_init_restore(void);
extern int kerndat_vdso_fill_symtable(void);
extern int kerndat_vdso_preserves_hint(void);

extern int parasite_fixup_vdso(struct parasite_ctl *ctl, pid_t pid,
			       struct vm_area_list *vma_area_list);

#ifdef CONFIG_COMPAT
extern void compat_vdso_helper(struct vdso_maps *native, int pipe_fd,
		int err_fd, void *vdso_buf, size_t buf_size);
#endif

#else /* CONFIG_VDSO */

#define vdso_init_dump()					(0)
#define vdso_init_restore()					(0)
#define kerndat_vdso_fill_symtable()				(0)
#define kerndat_vdso_preserves_hint()				(0)
#define parasite_fixup_vdso(ctl, pid, vma_area_list)		(0)

#endif /* CONFIG_VDSO */

#endif /* __CR_VDSO_H__ */
