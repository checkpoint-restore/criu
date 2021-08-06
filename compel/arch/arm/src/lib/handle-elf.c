#include <errno.h>
#include <string.h>

#include "handle-elf.h"
#include "log.h"
#include "piegen.h"

static const unsigned char __maybe_unused elf_ident_32[EI_NIDENT] = {
	0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x00, /* clang-format */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

int handle_binary(void *mem, size_t size)
{
	if (memcmp(mem, elf_ident_32, sizeof(elf_ident_32)) == 0)
		return handle_elf_arm(mem, size);

	pr_err("Unsupported Elf format detected\n");
	return -EINVAL;
}
