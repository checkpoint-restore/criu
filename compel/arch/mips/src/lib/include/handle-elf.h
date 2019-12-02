#ifndef COMPEL_HANDLE_ELF_H__
#define COMPEL_HANDLE_ELF_H__

#include "elf64-types.h"

#define ELF_MIPS
#define __handle_elf				handle_elf_mips
//#define handle_elf_mips __handle_elf
#define arch_is_machine_supported(e_machine)	(e_machine == EM_MIPS)

extern int handle_elf_mips(void *mem, size_t size);

#endif /* COMPEL_HANDLE_ELF_H__ */
