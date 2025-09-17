#include <string.h>
#include <errno.h>

#include "handle-elf.h"
#include "piegen.h"
#include "log.h"

extern int __handle_elf(void *mem, size_t size);

int handle_binary(void *mem, size_t size)
{
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)mem;

	/* check ELF magic */
	if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
	    ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
	    ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
	    ehdr->e_ident[EI_MAG3] != ELFMAG3) {
		pr_err("Invalid ELF magic\n");
		return -EINVAL;
	}

	/* check ELF class and data encoding */
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
	    ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
		pr_err("Unsupported ELF class or data encoding\n");
		return -EINVAL;
	}

	if (ehdr->e_ident[EI_ABIVERSION] != 0) {
		pr_warn("Unusual ABI version: %d\n", ehdr->e_ident[EI_ABIVERSION]);
	}

	return __handle_elf(mem, size);
}
