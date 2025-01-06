#ifndef COMPEL_HANDLE_ELF_H__
#define COMPEL_HANDLE_ELF_H__

#include "elf64-types.h"

#define ELF_S390

#define __handle_elf			     handle_elf_s390
#define arch_is_machine_supported(e_machine) (e_machine == EM_S390)

int handle_elf_s390(void *mem, size_t size);

#endif /* COMPEL_HANDLE_ELF_H__ */
