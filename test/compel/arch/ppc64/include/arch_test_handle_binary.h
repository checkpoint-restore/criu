#ifndef __ARCH_TEST_HANDLE_BINARY__
#define __ARCH_TEST_HANDLE_BINARY__

#include <string.h>

#include "uapi/elf64-types.h"
#define arch_run_tests(mem) __run_tests(mem, "")
extern int __run_tests(void *mem, const char *msg);

static __maybe_unused void arch_test_set_elf_hdr_ident(void *mem)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	memcpy(mem, elf_ident_64_le, sizeof(elf_ident_64_le));
#else
	memcpy(mem, elf_ident_64_be, sizeof(elf_ident_64_be));
#endif
}

static __maybe_unused void arch_test_set_elf_hdr_machine(Ehdr_t *hdr)
{
	hdr->e_machine = EM_PPC64;
}

#endif /* __ARCH_TEST_HANDLE_BINARY__ */
