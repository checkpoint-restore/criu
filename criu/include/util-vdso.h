#ifndef __CR_UTIL_VDSO_H__
#define __CR_UTIL_VDSO_H__

/*
 * VDSO management common definitions.
 *
 * This header file is included by the criu main code and the parasite code.
 * It contains definitions shared by these 2 parts.
 *
 * This file should not be included except in pie/util-vdso.c, include/vdso.h
 * and include/parasite-vdso.h
 */

#include <sys/types.h>

/*
 * Each architecture must export:
 *	VDSO_SYMBOL_MAX, the number of vDSO symbols to manage
 *	ARCH_VDSO_SYMBOLS, a table of string containing the vDSO symbol names
 *	vdso_redirect_calls, a service called to redirect the vDSO symbols in
 *	 the parasite code.
 */
#include "asm/vdso.h"

struct vdso_symbol {
	char name[32];
	unsigned long offset;
};

struct vdso_symtable {
	unsigned long vdso_size;
	unsigned long vvar_size;
	unsigned long vvar_vclock_size;
	struct vdso_symbol symbols[VDSO_SYMBOL_MAX];
	bool vdso_before_vvar; /* order of vdso/vvar pair */
};

struct vdso_maps {
	unsigned long vdso_start;
	unsigned long vvar_start;
	struct vdso_symtable sym;
	bool compatible;
};

static inline bool vdso_is_present(struct vdso_maps *m)
{
	return m->vdso_start != VDSO_BAD_ADDR;
}

#define VDSO_SYMBOL_INIT                 \
	{                                \
		.offset = VDSO_BAD_ADDR, \
	}

#define VDSO_SYMTABLE_INIT                      \
	{                                       \
		.vdso_size	= VDSO_BAD_SIZE,			\
		.vvar_size	= VVAR_BAD_SIZE,			\
		.symbols		= {				\
			[0 ... VDSO_SYMBOL_MAX - 1] =			\
				(struct vdso_symbol)VDSO_SYMBOL_INIT,	\
			},						\
		.vdso_before_vvar	= false, \
	}

#define VDSO_MAPS_INIT                                                                               \
	{                                                                                            \
		.vdso_start = VDSO_BAD_ADDR, .vvar_start = VVAR_BAD_ADDR, .sym = VDSO_SYMTABLE_INIT, \
	}

#ifdef CONFIG_VDSO_32

#define Ehdr_t Elf32_Ehdr
#define Sym_t  Elf32_Sym
#define Phdr_t Elf32_Phdr
#define Word_t Elf32_Word
#define Dyn_t  Elf32_Dyn

#ifndef ELF_ST_TYPE
#define ELF_ST_TYPE ELF32_ST_TYPE
#endif
#ifndef ELF_ST_BIND
#define ELF_ST_BIND ELF32_ST_BIND
#endif

#define vdso_fill_symtable vdso_fill_symtable_compat

#else /* CONFIG_VDSO_32 */

#define Ehdr_t Elf64_Ehdr
#define Sym_t  Elf64_Sym
#define Phdr_t Elf64_Phdr
#define Word_t Elf64_Word
#define Dyn_t  Elf64_Dyn

#ifndef ELF_ST_TYPE
#define ELF_ST_TYPE ELF64_ST_TYPE
#endif
#ifndef ELF_ST_BIND
#define ELF_ST_BIND ELF64_ST_BIND
#endif

#endif /* CONFIG_VDSO_32 */

extern int vdso_fill_symtable(uintptr_t mem, size_t size, struct vdso_symtable *t);

#endif /* __CR_UTIL_VDSO_H__ */
