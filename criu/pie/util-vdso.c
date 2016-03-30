#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <elf.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "asm/string.h"
#include "asm/types.h"

#include "image.h"
#include "util-vdso.h"
#include "vma.h"
#include "log.h"
#include "bug.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif
#define LOG_PREFIX "vdso: "

/* Check if pointer is out-of-bound */
static bool __ptr_oob(uintptr_t ptr, uintptr_t start, size_t size)
{
	uintptr_t end = start + size;

	return ptr > end || ptr < start;
}

/*
 * Elf hash, see format specification.
 */
static unsigned long elf_hash(const unsigned char *name)
{
	unsigned long h = 0, g;

	while (*name) {
		h = (h << 4) + *name++;
		g = h & 0xf0000000ul;
		if (g)
			h ^= g >> 24;
		h &= ~g;
	}
	return h;
}

static int has_elf_identity(Ehdr_t *ehdr)
{
	/*
	 * See Elf specification for this magic values.
	 */
#if defined(CONFIG_X86_32)
	static const char elf_ident[] = {
		0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
#else
	static const char elf_ident[] = {
		0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
#endif

	BUILD_BUG_ON(sizeof(elf_ident) != sizeof(ehdr->e_ident));

	if (builtin_memcmp(ehdr->e_ident, elf_ident, sizeof(elf_ident))) {
		pr_err("Elf header magic mismatch\n");
		return false;
	}

	return true;
}

int vdso_fill_symtable(uintptr_t mem, size_t size, struct vdso_symtable *t)
{
	const char *vdso_symbols[VDSO_SYMBOL_MAX] = {
		ARCH_VDSO_SYMBOLS
	};

	Phdr_t *dynamic = NULL, *load = NULL;
	Ehdr_t *ehdr = (void *)mem;
	Dyn_t *dyn_strtab = NULL;
	Dyn_t *dyn_symtab = NULL;
	Dyn_t *dyn_strsz = NULL;
	Dyn_t *dyn_syment = NULL;
	Dyn_t *dyn_hash = NULL;
	Word_t *hash = NULL;
	Phdr_t *phdr;
	Dyn_t *d;

	Word_t *bucket, *chain;
	Word_t nbucket, nchain;

	uintptr_t addr;

	char *dynsymbol_names;
	unsigned int i, j, k;

	pr_debug("Parsing at %lx %lx\n", (long)mem, (long)mem + (long)size);

	/*
	 * Make sure it's a file we support.
	 */
	if (!has_elf_identity(ehdr))
		return -EINVAL;

	/*
	 * We need PT_LOAD and PT_DYNAMIC here. Each once.
	 */
	addr = mem + ehdr->e_phoff;
	for (i = 0; i < ehdr->e_phnum; i++, addr += sizeof(Phdr_t)) {
		if (__ptr_oob(addr, mem, size))
			goto err_oob;
		phdr = (void *)addr;
		switch (phdr->p_type) {
		case PT_DYNAMIC:
			if (dynamic) {
				pr_err("Second PT_DYNAMIC header\n");
				return -EINVAL;
			}
			dynamic = phdr;
			break;
		case PT_LOAD:
			if (load) {
				pr_err("Second PT_LOAD header\n");
				return -EINVAL;
			}
			load = phdr;
			break;
		}
	}

	if (!load || !dynamic) {
		pr_err("One of obligated program headers is missed\n");
		return -EINVAL;
	}

	pr_debug("PT_LOAD p_vaddr: %lx\n", (unsigned long)load->p_vaddr);

	/*
	 * Dynamic section tags should provide us the rest of information
	 * needed. Note that we're interested in a small set of tags.
	 */
	addr = mem + dynamic->p_offset;
	for (i = 0; i < dynamic->p_filesz / sizeof(*d);
			i++, addr += sizeof(Dyn_t)) {
		if (__ptr_oob(addr, mem, size))
			goto err_oob;
		d = (void *)addr;

		if (d->d_tag == DT_NULL) {
			break;
		} else if (d->d_tag == DT_STRTAB) {
			dyn_strtab = d;
			pr_debug("DT_STRTAB: %lx\n", (unsigned long)d->d_un.d_ptr);
		} else if (d->d_tag == DT_SYMTAB) {
			dyn_symtab = d;
			pr_debug("DT_SYMTAB: %lx\n", (unsigned long)d->d_un.d_ptr);
		} else if (d->d_tag == DT_STRSZ) {
			dyn_strsz = d;
			pr_debug("DT_STRSZ: %lx\n", (unsigned long)d->d_un.d_val);
		} else if (d->d_tag == DT_SYMENT) {
			dyn_syment = d;
			pr_debug("DT_SYMENT: %lx\n", (unsigned long)d->d_un.d_val);
		} else if (d->d_tag == DT_HASH) {
			dyn_hash = d;
			pr_debug("DT_HASH: %lx\n", (unsigned long)d->d_un.d_ptr);
		}
	}

	if (!dyn_strtab || !dyn_symtab || !dyn_strsz || !dyn_syment || !dyn_hash) {
		pr_err("Not all dynamic entries are present\n");
		return -EINVAL;
	}

	addr = mem + dyn_strtab->d_un.d_val - load->p_vaddr;
	if (__ptr_oob(addr, mem, size))
		goto err_oob;
	dynsymbol_names = (void *)addr;

	addr = mem + dyn_hash->d_un.d_ptr - load->p_vaddr;
	if (__ptr_oob(addr, mem, size))
		goto err_oob;
	hash = (void *)addr;

	nbucket = hash[0];
	nchain = hash[1];
	bucket = &hash[2];
	chain = &hash[nbucket + 2];

	pr_debug("nbucket %lx nchain %lx bucket %lx chain %lx\n",
		 (long)nbucket, (long)nchain, (unsigned long)bucket, (unsigned long)chain);

	for (i = 0; i < VDSO_SYMBOL_MAX; i++) {
		const char * symbol = vdso_symbols[i];
		k = elf_hash((const unsigned char *)symbol);

		for (j = bucket[k % nbucket]; j < nchain && chain[j] != STN_UNDEF; j = chain[j]) {
			addr = mem + dyn_symtab->d_un.d_ptr - load->p_vaddr;
			Sym_t *sym;
			char *name;

			addr += sizeof(Sym_t)*j;
			if (__ptr_oob(addr, mem, size))
				continue;
			sym = (void *)addr;

			if (ELF_ST_TYPE(sym->st_info) != STT_FUNC &&
			    ELF_ST_BIND(sym->st_info) != STB_GLOBAL)
				continue;

			addr = (uintptr_t)dynsymbol_names + sym->st_name;
			if (__ptr_oob(addr, mem, size))
				continue;
			name = (void *)addr;

			if (builtin_strcmp(name, symbol))
				continue;

			builtin_memcpy(t->symbols[i].name, name, sizeof(t->symbols[i].name));
			t->symbols[i].offset = (unsigned long)sym->st_value - load->p_vaddr;
			break;
		}
	}

	return 0;

err_oob:
	pr_err("Corrupted Elf data\n");
	return -EFAULT;
}

