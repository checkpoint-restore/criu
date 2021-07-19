#ifndef __ARCH_TEST_HANDLE_BINARY__
#define __ARCH_TEST_HANDLE_BINARY__

#include <string.h>

#include "uapi/elf32-types.h"
#define arch_run_tests(mem) __run_tests(mem, "")
extern int __run_tests(void *mem, const char *msg);

static __maybe_unused void arch_test_set_elf_hdr_ident(void *mem)
{
	memcpy(mem, elf_ident_32, sizeof(elf_ident_32));
}

static __maybe_unused void arch_test_set_elf_hdr_machine(Ehdr_t *hdr)
{
	hdr->e_machine = EM_ARM;
}

#endif /* __ARCH_TEST_HANDLE_BINARY__ */
