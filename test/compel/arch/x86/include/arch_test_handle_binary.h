#ifndef __ARCH_TEST_HANDLE_BINARY__
#define __ARCH_TEST_HANDLE_BINARY__

#include <string.h>

#ifdef CONFIG_X86_64
#include "uapi/elf64-types.h"
#define __run_tests	run_tests_64

static __maybe_unused void arch_test_set_elf_hdr_ident(void *mem)
{
	memcpy(mem, elf_ident_64_le, sizeof(elf_ident_64_le));
}

static __maybe_unused void arch_test_set_elf_hdr_machine(Ehdr_t *hdr)
{
	hdr->e_machine = EM_X86_64;
}

#else /* !CONFIG_X86_64 */

#include "uapi/elf32-types.h"
#define __run_tests	run_tests_32

static __maybe_unused void arch_test_set_elf_hdr_ident(void *mem)
{
	memcpy(mem, elf_ident_32, sizeof(elf_ident_32));
}

static __maybe_unused void arch_test_set_elf_hdr_machine(Ehdr_t *hdr)
{
	hdr->e_machine = EM_386;
}

#endif /* CONFIG_X86_32 */

extern int run_tests_64(void *mem, const char *msg);
extern int run_tests_32(void *mem, const char *msg);

static __maybe_unused int arch_run_tests(void *mem)
{
	int ret;

	ret = run_tests_64(mem, "(64-bit ELF)");
	ret += run_tests_32(mem, "(32-bit ELF)");

	return ret;
}
#endif /* __ARCH_TEST_HANDLE_BINARY__ */
