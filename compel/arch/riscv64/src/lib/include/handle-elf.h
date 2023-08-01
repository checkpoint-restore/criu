#ifndef COMPEL_HANDLE_ELF_H__
#define COMPEL_HANDLE_ELF_H__

#include "elf64-types.h"

#define __handle_elf handle_elf_riscv64
#define ELF_RISCV
#define arch_is_machine_supported(e_machine) (e_machine == EM_RISCV)

extern int handle_elf_riscv64(void *mem, size_t size);

#endif /* COMPEL_HANDLE_ELF_H__ */