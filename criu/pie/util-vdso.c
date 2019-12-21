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

#include "image.h"
#include "util-vdso.h"
#include "vma.h"
#include "log.h"
#include "common/bug.h"

#ifdef CR_NOGLIBC
# include <compel/plugins/std/string.h>
#else
# include <string.h>
# define std_strncmp strncmp
#endif

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif
#define LOG_PREFIX "vdso: "

/* Check if pointer is out-of-bound */
static bool __ptr_oob(uintptr_t ptr, uintptr_t start, size_t size)
{
	uintptr_t end = start + size;

	return ptr >= end || ptr < start;
}

/* Check if pointed structure's end is out-of-bound */
static bool __ptr_struct_end_oob(uintptr_t ptr, size_t struct_size,
				uintptr_t start, size_t size)
{
	return __ptr_oob(ptr + struct_size - 1, start, size);
}

/* Check if pointed structure is out-of-bound */
static bool __ptr_struct_oob(uintptr_t ptr, size_t struct_size,
				uintptr_t start, size_t size)
{
	return __ptr_oob(ptr, start, size) ||
		__ptr_struct_end_oob(ptr, struct_size, start, size);
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

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BORD ELFDATA2MSB /* 0x02 */
#else
#define BORD ELFDATA2LSB /* 0x01 */
#endif

static int has_elf_identity(Ehdr_t *ehdr)
{
	/*
	 * See Elf specification for this magic values.
	 */
#if defined(CONFIG_VDSO_32)
	static const char elf_ident[] = {
		0x7f, 0x45, 0x4c, 0x46, 0x01, BORD, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
#else
	static const char elf_ident[] = {
		0x7f, 0x45, 0x4c, 0x46, 0x02, BORD, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
#endif

	BUILD_BUG_ON(sizeof(elf_ident) != sizeof(ehdr->e_ident));

	if (memcmp(ehdr->e_ident, elf_ident, sizeof(elf_ident))) {
		pr_err("ELF header magic mismatch\n");
		return false;
	}

	return true;
}

static int parse_elf_phdr(uintptr_t mem, size_t size,
		Phdr_t **dynamic, Phdr_t **load)
{
	Ehdr_t *ehdr = (void *)mem;
	uintptr_t addr;
	Phdr_t *phdr;
	int i;

	if (__ptr_struct_end_oob(mem, sizeof(Ehdr_t), mem, size))
		goto err_oob;
	/*
	 * Make sure it's a file we support.
	 */
	if (!has_elf_identity(ehdr))
		return -EINVAL;

	addr = mem + ehdr->e_phoff;
	if (__ptr_oob(addr, mem, size))
		goto err_oob;

	for (i = 0; i < ehdr->e_phnum; i++, addr += sizeof(Phdr_t)) {
		if (__ptr_struct_end_oob(addr, sizeof(Phdr_t), mem, size))
			goto err_oob;

		phdr = (void *)addr;
		switch (phdr->p_type) {
		case PT_DYNAMIC:
			if (*dynamic) {
				pr_err("Second PT_DYNAMIC header\n");
				return -EINVAL;
			}
			*dynamic = phdr;
			break;
		case PT_LOAD:
			if (*load) {
				pr_err("Second PT_LOAD header\n");
				return -EINVAL;
			}
			*load = phdr;
			break;
		}
	}
	return 0;

err_oob:
	pr_err("Corrupted Elf phdr\n");
	return -EFAULT;
}

/*
 * Parse dynamic program header.
 * Output parameters are:
 *   @dyn_strtab - address of the symbol table
 *   @dyn_symtab - address of the string table section
 *   @dyn_hash   - address of the symbol hash table
 */
static int parse_elf_dynamic(uintptr_t mem, size_t size, Phdr_t *dynamic,
		Dyn_t **dyn_strtab, Dyn_t **dyn_symtab, Dyn_t **dyn_hash)
{
	Dyn_t *dyn_syment = NULL;
	Dyn_t *dyn_strsz = NULL;
	uintptr_t addr;
	Dyn_t *d;
	int i;

	addr = mem + dynamic->p_offset;
	if (__ptr_oob(addr, mem, size))
		goto err_oob;

	for (i = 0; i < dynamic->p_filesz / sizeof(*d);
			i++, addr += sizeof(Dyn_t)) {
		if (__ptr_struct_end_oob(addr, sizeof(Dyn_t), mem, size))
			goto err_oob;
		d = (void *)addr;

		if (d->d_tag == DT_NULL) {
			break;
		} else if (d->d_tag == DT_STRTAB) {
			*dyn_strtab = d;
			pr_debug("DT_STRTAB: %lx\n", (unsigned long)d->d_un.d_ptr);
		} else if (d->d_tag == DT_SYMTAB) {
			*dyn_symtab = d;
			pr_debug("DT_SYMTAB: %lx\n", (unsigned long)d->d_un.d_ptr);
		} else if (d->d_tag == DT_STRSZ) {
			dyn_strsz = d;
			pr_debug("DT_STRSZ: %lx\n", (unsigned long)d->d_un.d_val);
		} else if (d->d_tag == DT_SYMENT) {
			dyn_syment = d;
			pr_debug("DT_SYMENT: %lx\n", (unsigned long)d->d_un.d_val);
		} else if (d->d_tag == DT_HASH) {
			*dyn_hash = d;
			pr_debug("DT_HASH: %lx\n", (unsigned long)d->d_un.d_ptr);
		}
	}

	if (!*dyn_strtab || !*dyn_symtab || !dyn_strsz || !dyn_syment || !*dyn_hash) {
		pr_err("Not all dynamic entries are present\n");
		return -EINVAL;
	}

	return 0;

err_oob:
	pr_err("Corrupted Elf dynamic section\n");
	return -EFAULT;
}

/* On s390x Hash_t is 64 bit */
#ifdef __s390x__
typedef unsigned long Hash_t;
#else
typedef Word_t Hash_t;
#endif

static void parse_elf_symbols(uintptr_t mem, size_t size, Phdr_t *load,
		struct vdso_symtable *t, uintptr_t dynsymbol_names,
		Hash_t *hash, Dyn_t *dyn_symtab)
{
	const char *vdso_symbols[VDSO_SYMBOL_MAX] = {
		ARCH_VDSO_SYMBOLS
	};
	const size_t vdso_symbol_length = sizeof(t->symbols[0].name);

	Hash_t nbucket, nchain;
	Hash_t *bucket, *chain;

	unsigned int i, j, k;
	uintptr_t addr;

	nbucket = hash[0];
	nchain = hash[1];
	bucket = &hash[2];
	chain = &hash[nbucket + 2];

	pr_debug("nbucket %lx nchain %lx bucket %lx chain %lx\n",
		 (long)nbucket, (long)nchain, (unsigned long)bucket, (unsigned long)chain);

	for (i = 0; i < VDSO_SYMBOL_MAX; i++) {
		const char * symbol = vdso_symbols[i];
		k = elf_hash((const unsigned char *)symbol);

		for (j = bucket[k % nbucket]; j < nchain && j != STN_UNDEF; j = chain[j]) {
			Sym_t *sym;
			char *name;

			addr = mem + dyn_symtab->d_un.d_ptr - load->p_vaddr;

			addr += sizeof(Sym_t)*j;
			if (__ptr_struct_oob(addr, sizeof(Sym_t), mem, size))
				continue;
			sym = (void *)addr;

			if (ELF_ST_TYPE(sym->st_info) != STT_FUNC &&
			    ELF_ST_BIND(sym->st_info) != STB_GLOBAL)
				continue;

			addr = dynsymbol_names + sym->st_name;
			if (__ptr_struct_oob(addr, vdso_symbol_length, mem, size))
				continue;
			name = (void *)addr;

			if (std_strncmp(name, symbol, vdso_symbol_length))
				continue;

			memcpy(t->symbols[i].name, name, vdso_symbol_length);
			t->symbols[i].offset = (unsigned long)sym->st_value - load->p_vaddr;
			break;
		}
	}
}

int vdso_fill_symtable(uintptr_t mem, size_t size, struct vdso_symtable *t)
{
	Phdr_t *dynamic = NULL, *load = NULL;
	Dyn_t *dyn_strtab = NULL;
	Dyn_t *dyn_symtab = NULL;
	Dyn_t *dyn_hash = NULL;
	Hash_t *hash = NULL;

	uintptr_t dynsymbol_names;
	uintptr_t addr;
	int ret;

	pr_debug("Parsing at %lx %lx\n", (long)mem, (long)mem + (long)size);

	/*
	 * We need PT_LOAD and PT_DYNAMIC here. Each once.
	 */
	ret = parse_elf_phdr(mem, size, &dynamic, &load);
	if (ret < 0)
		return ret;
	if (!load || !dynamic) {
		pr_err("One of obligated program headers is missed\n");
		return -EINVAL;
	}

	pr_debug("PT_LOAD p_vaddr: %lx\n", (unsigned long)load->p_vaddr);

	/*
	 * Dynamic section tags should provide us the rest of information
	 * needed. Note that we're interested in a small set of tags.
	 */

	ret = parse_elf_dynamic(mem, size, dynamic,
			&dyn_strtab, &dyn_symtab, &dyn_hash);
	if (ret < 0)
		return ret;

	addr = mem + dyn_strtab->d_un.d_val - load->p_vaddr;
	if (__ptr_oob(addr, mem, size))
		goto err_oob;
	dynsymbol_names = addr;

	addr = mem + dyn_hash->d_un.d_ptr - load->p_vaddr;
	if (__ptr_struct_oob(addr, sizeof(Word_t), mem, size))
		goto err_oob;
	hash = (void *)addr;

	parse_elf_symbols(mem, size, load, t, dynsymbol_names, hash, dyn_symtab);

	return 0;

err_oob:
	pr_err("Corrupted Elf symbols/hash\n");
	return -EFAULT;
}

