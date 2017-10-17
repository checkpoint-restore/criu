#ifndef COMPEL_HANDLE_ELF_H__
#define COMPEL_HANDLE_ELF_H__

#include "elf64-types.h"

#define ELF_X86_64

#ifndef R_X86_64_GOTPCRELX
# define R_X86_64_GOTPCRELX			41
#endif

#ifndef R_X86_64_REX_GOTPCRELX
# define R_X86_64_REX_GOTPCRELX			42
#endif

#define __handle_elf				handle_elf_x86_64
#define arch_is_machine_supported(e_machine)	(e_machine == EM_X86_64)

extern int handle_elf_x86_32(void *mem, size_t size);
extern int handle_elf_x86_64(void *mem, size_t size);

#endif /* COMPEL_HANDLE_ELF_H__ */
