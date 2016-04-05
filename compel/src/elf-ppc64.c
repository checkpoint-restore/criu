#define ELF_PPC64
#define handle_elf	handle_elf_ppc64

#define Ehdr_t		Elf64_Ehdr
#define Shdr_t		Elf64_Shdr
#define Sym_t		Elf64_Sym
#define Rel_t		Elf64_Rel
#define Rela_t		Elf64_Rela

#define ELF_ST_TYPE	ELF64_ST_TYPE
#define ELF_ST_BIND	ELF64_ST_BIND

#define ELF_R_SYM	ELF64_R_SYM
#define ELF_R_TYPE	ELF64_R_TYPE

#include "elf.c"
