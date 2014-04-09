#ifndef __CR_ASM_VDSO_H__
#define __CR_ASM_VDSO_H__

#include <sys/types.h>

#include "protobuf/vma.pb-c.h"


/*
 * This is a minimal amount of symbols
 * we should support at the moment.
 */
enum {
	VDSO_SYMBOL_CLOCK_GETTIME,
	VDSO_SYMBOL_GETCPU,
	VDSO_SYMBOL_GETTIMEOFDAY,
	VDSO_SYMBOL_TIME,

	VDSO_SYMBOL_MAX
};

#define VDSO_SYMBOL_CLOCK_GETTIME_NAME	"__vdso_clock_gettime"
#define VDSO_SYMBOL_GETCPU_NAME		"__vdso_getcpu"
#define VDSO_SYMBOL_GETTIMEOFDAY_NAME	"__vdso_gettimeofday"
#define VDSO_SYMBOL_TIME_NAME		"__vdso_time"


#define DECLARE_VDSO(ident_name, symtab_name)					\
										\
char ident_name[] = {								\
	0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,				\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,				\
};										\
										\
char *symtab_name[VDSO_SYMBOL_MAX] = {						\
	[VDSO_SYMBOL_CLOCK_GETTIME]	= VDSO_SYMBOL_CLOCK_GETTIME_NAME,	\
	[VDSO_SYMBOL_GETCPU]		= VDSO_SYMBOL_GETCPU_NAME,		\
	[VDSO_SYMBOL_GETTIMEOFDAY]	= VDSO_SYMBOL_GETTIMEOFDAY_NAME,	\
	[VDSO_SYMBOL_TIME]		= VDSO_SYMBOL_TIME_NAME,		\
};


struct vdso_symtable;
struct parasite_ctl;
struct vm_area_list;

extern int vdso_redirect_calls(void *base_to, void *base_from, struct vdso_symtable *to, struct vdso_symtable *from);
extern int parasite_fixup_vdso(struct parasite_ctl *ctl, pid_t pid,
			       struct vm_area_list *vma_area_list);

#endif /* __CR_ASM_VDSO_H__ */
