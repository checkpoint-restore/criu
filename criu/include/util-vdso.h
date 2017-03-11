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
	char			name[32];
	unsigned long		offset;
};

struct vdso_symtable {
	unsigned long		vma_start;
	unsigned long		vma_end;
	unsigned long		vvar_start;
	unsigned long		vvar_end;
	struct vdso_symbol	symbols[VDSO_SYMBOL_MAX];
};

#define VDSO_SYMBOL_INIT	{ .offset = VDSO_BAD_ADDR, }

#define VDSO_SYMTABLE_INIT						\
	{								\
		.vma_start	= VDSO_BAD_ADDR,			\
		.vma_end	= VDSO_BAD_ADDR,			\
		.vvar_start	= VVAR_BAD_ADDR,			\
		.vvar_end	= VVAR_BAD_ADDR,			\
		.symbols		= {				\
			[0 ... VDSO_SYMBOL_MAX - 1] =			\
				(struct vdso_symbol)VDSO_SYMBOL_INIT,	\
			},						\
	}

#ifdef CONFIG_VDSO_32

#define Ehdr_t		Elf32_Ehdr
#define Sym_t		Elf32_Sym
#define Phdr_t		Elf32_Phdr
#define Word_t		Elf32_Word
#define Dyn_t		Elf32_Dyn

#define ELF_ST_TYPE	ELF32_ST_TYPE
#define ELF_ST_BIND	ELF32_ST_BIND

#else /* CONFIG_VDSO_32 */

#define Ehdr_t		Elf64_Ehdr
#define Sym_t		Elf64_Sym
#define Phdr_t		Elf64_Phdr
#define Word_t		Elf64_Word
#define Dyn_t		Elf64_Dyn

#ifndef ELF_ST_TYPE
#define ELF_ST_TYPE	ELF64_ST_TYPE
#endif
#ifndef ELF_ST_BIND
#define ELF_ST_BIND	ELF64_ST_BIND
#endif

#endif /* CONFIG_VDSO_32 */

/* Size of VMA associated with vdso */
static inline unsigned long vdso_vma_size(struct vdso_symtable *t)
{
	return t->vma_end - t->vma_start;
}

static inline unsigned long vvar_vma_size(struct vdso_symtable *t)
{
	return t->vvar_end - t->vvar_start;
}

#if defined(CONFIG_VDSO_32)
# define vdso_fill_symtable vdso_fill_symtable_compat
#endif

extern int vdso_fill_symtable(uintptr_t mem, size_t size, struct vdso_symtable *t);
#if defined(CONFIG_X86_64) && defined(CONFIG_COMPAT)
#ifndef ARCH_MAP_VDSO_32
# define ARCH_MAP_VDSO_32	0x2002
#endif
extern int vdso_fill_symtable_compat(uintptr_t mem, size_t size,
		struct vdso_symtable *t);
#endif

#endif /* __CR_UTIL_VDSO_H__ */
