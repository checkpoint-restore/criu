#ifndef __COMPEL_HANDLE_ELF_H__
#define __COMPEL_HANDLE_ELF_H__

#ifdef CONFIG_X86_32

#include "uapi/elf32-types.h"
#define ELF_X86_32
#define handle_elf	handle_elf_x86_32

#else /* CONFIG_X86_64 */

#include "uapi/elf64-types.h"
#define ELF_X86_64
#define handle_elf	handle_elf_x86_64

#endif

#endif /* __COMPEL_HANDLE_ELF_H__ */
