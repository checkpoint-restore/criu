#ifndef __COMPEL_HANDLE_ELF_H__
#define __COMPEL_HANDLE_ELF_H__

#ifdef CONFIG_X86_32

#include "uapi/elf32-types.h"
#define ELF_X86_32
#define __handle_elf	handle_elf_x86_32

#else /* CONFIG_X86_64 */

#include "uapi/elf64-types.h"
#define ELF_X86_64
#define __handle_elf	handle_elf_x86_64

#endif

extern int handle_elf_x86_32(void *mem, size_t size);
extern int handle_elf_x86_64(void *mem, size_t size);

#endif /* __COMPEL_HANDLE_ELF_H__ */
