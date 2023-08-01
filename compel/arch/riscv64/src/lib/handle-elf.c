#include <string.h>
#include <errno.h>

#include "handle-elf.h"
#include "piegen.h"
#include "log.h"

static const unsigned char __maybe_unused elf_ident_64_le[EI_NIDENT] = {
	0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, /* clang-format */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const unsigned char __maybe_unused elf_ident_64_be[EI_NIDENT] = {
	0x7f, 0x45, 0x4c, 0x46, 0x02, 0x02, 0x01, 0x00, /* clang-format */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

int handle_binary(void *mem, size_t size)
{
	const unsigned char *elf_ident =
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		elf_ident_64_le;
#else
		elf_ident_64_be;
#endif

	if (memcmp(mem, elf_ident, sizeof(elf_ident_64_le)) == 0)
		return handle_elf_riscv64(mem, size);

	pr_err("Unsupported Elf format detected\n");
	return -EINVAL;
}