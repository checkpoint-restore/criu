#include <string.h>

#include "uapi/piegen-err.h"
#include "piegen.h"

#include "arch_test_handle_binary.h"

extern int launch_test(void *mem, int expected_ret, const char *test_name);

static void set_elf_hdr_relocatable(Ehdr_t *hdr)
{
	hdr->e_type = ET_REL;
	hdr->e_version = EV_CURRENT;
}

static int test_prepare_elf_header(void *elf)
{
	memset(elf, 0, sizeof(Ehdr_t));
	if (launch_test(elf, -E_NOT_ELF, "check zero ELF header"))
		return -1;

	arch_test_set_elf_hdr_ident(elf);
	if (launch_test(elf, -E_NOT_ELF, "check non-supported ELF header"))
		return -1;

	arch_test_set_elf_hdr_machine(elf);
	if (launch_test(elf, -E_NOT_ELF, "check non-relocatable ELF header"))
		return -1;

	set_elf_hdr_relocatable(elf);

	return 0;
}

void __run_tests(void *mem)
{
	if (test_prepare_elf_header(mem))
		return;
}
