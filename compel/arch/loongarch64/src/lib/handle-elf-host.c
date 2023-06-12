#include <string.h>
#include <errno.h>

#include "handle-elf.h"
#include "piegen.h"
#include "log.h"

static const unsigned char __maybe_unused elf_ident_64_le[EI_NIDENT] = {
	0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, /* clang-format */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

extern int __handle_elf(void *mem, size_t size);

int handle_binary(void *mem, size_t size)
{
	if (memcmp(mem, elf_ident_64_le, sizeof(elf_ident_64_le)) == 0)
		return __handle_elf(mem, size);

	pr_err("Unsupported Elf format detected\n");
	return -EINVAL;
}
