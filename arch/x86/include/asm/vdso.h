#ifndef __CR_ASM_VDSO_H__
#define __CR_ASM_VDSO_H__

#include <sys/types.h>

#include "protobuf/vma.pb-c.h"

struct vdso_symtable;
struct parasite_ctl;
struct vm_area_list;

extern int vdso_redirect_calls(void *base_to, void *base_from, struct vdso_symtable *to, struct vdso_symtable *from);
extern int vdso_fill_symtable(char *mem, size_t size,struct vdso_symtable *t);
extern int vdso_remap(char *who, unsigned long from, unsigned long to, size_t size);
extern int vdso_proxify(char *who, struct vdso_symtable *sym_rt, VmaEntry *vma_entry, unsigned long vdso_rt_parked_at);
extern int parasite_fixup_vdso(struct parasite_ctl *ctl, pid_t pid,
			       struct vm_area_list *vma_area_list);

#endif /* __CR_ASM_VDSO_H__ */
