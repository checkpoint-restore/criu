#include <string.h>

#include "uapi/compel.h"

#include "handle-elf.h"
#include "piegen.h"
#include "log.h"

static const unsigned char __maybe_unused
elf_ident_64[EI_NIDENT] = {
	0x7f, 0x45, 0x4c, 0x46, 0x02, 0x02, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

int handle_binary(void *mem, size_t size)
{
	if (memcmp(mem, elf_ident_64, sizeof(elf_ident_64)) == 0)
		return handle_elf_s390(mem, size);

	pr_err("Unsupported Elf format detected\n");
	return -EINVAL;
}
