#include <string.h>

#include "uapi/piegen-err.h"
#include "piegen.h"

#include "arch_test_handle_binary.h"

extern int launch_test(void *mem, int expected_ret, const char *test_fmt, ...);
extern const size_t test_elf_buf_size;

static const unsigned int sections_nr = 1;

static void set_elf_hdr_relocatable(Ehdr_t *hdr)
{
	hdr->e_type = ET_REL;
	hdr->e_version = EV_CURRENT;
}

static int test_add_strings_section(void *elf, const char *msg)
{
	Ehdr_t *hdr = elf;
	Shdr_t *sec_strings_hdr;
	uintptr_t sections_table = (uintptr_t)elf + hdr->e_shoff;
	size_t sections_table_size = sections_nr*sizeof(hdr->e_shentsize);

	hdr->e_shnum = sections_nr;
	hdr->e_shstrndx = sections_nr; /* off-by-one */
	if (launch_test(elf, -E_NO_STR_SEC,
			"strings section's header oob of section table %s", msg))
		return -1;

	hdr->e_shstrndx = 0;
	sec_strings_hdr = (void *)sections_table;

	sec_strings_hdr->sh_offset = (Off_t)-1;
	if (launch_test(elf, -E_NO_STR_SEC, "strings section oob %s", msg))
		return -1;

	/* Put strings just right after sections table. */
	sec_strings_hdr->sh_offset = sections_table - (uintptr_t)elf +
						sections_table_size;
	return 0;
}

static int test_prepare_section_table(void *elf, const char *msg)
{
	Ehdr_t *hdr = elf;

	hdr->e_shoff = (Off_t)test_elf_buf_size;
	if (launch_test(elf, -E_NO_STR_SEC, "section table start oob %s", msg))
		return -1;

	/* Lets put sections table right after ELF header. */
	hdr->e_shoff = (Off_t) sizeof(Ehdr_t);
	hdr->e_shentsize = (Half_t) sizeof(Shdr_t);

	hdr->e_shnum = (Half_t)-1;
	if (launch_test(elf, -E_NO_STR_SEC, "too many sections in table %s", msg))
		return -1;

	if (test_add_strings_section(elf, msg))
		return -1;
	return 0;
}

static int test_prepare_elf_header(void *elf, const char *msg)
{
	memset(elf, 0, sizeof(Ehdr_t));
	if (launch_test(elf, -E_NOT_ELF, "zero ELF header %s", msg))
		return -1;

	arch_test_set_elf_hdr_ident(elf);
	if (launch_test(elf, -E_NOT_ELF, "unsupported ELF header %s", msg))
		return -1;

	arch_test_set_elf_hdr_machine(elf);
	if (launch_test(elf, -E_NOT_ELF, "non-relocatable ELF header %s", msg))
		return -1;

	set_elf_hdr_relocatable(elf);

	if (test_prepare_section_table(elf, msg))
		return -1;

	return 0;
}

void __run_tests(void *mem, const char *msg)
{
	if (test_prepare_elf_header(mem, msg))
		return;
}
