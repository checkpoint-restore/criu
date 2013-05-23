#ifndef __CR_ASM_VDSO_H__
#define __CR_ASM_VDSO_H__

#include <sys/types.h>

struct vdso_symtable;

extern int vdso_redirect_calls(void *base_to, void *base_from, struct vdso_symtable *to, struct vdso_symtable *from);
extern int vdso_fill_symtable(char *mem, size_t size,struct vdso_symtable *t);

#endif /* __CR_ASM_VDSO_H__ */
