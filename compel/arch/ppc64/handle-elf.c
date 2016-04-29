#include <string.h>

#include "piegen.h"
#include "handle-elf.h"

int handle_binary(void *mem, size_t size)
{
	const unsigned char *elf_ident =
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		elf_ident_64_le;
#else
		elf_ident_64_be;
#endif

	if (memcmp(mem, elf_ident, sizeof(elf_ident_64_le)) == 0)
		return handle_elf_ppc64(mem, size);

	pr_err("Unsupported Elf format detected\n");
	return -1;
}
