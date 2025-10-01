#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <elf.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "image.h"
#include "util-vdso.h"
#include "vma.h"
#include "log.h"
#include "common/bug.h"

#ifdef CR_NOGLIBC
#include <compel/plugins/std/string.h>
#else
#include <string.h>
#define std_strncmp strncmp
#endif

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "vdso: "

/* Check if pointer is out-of-bound */
static bool __ptr_oob(uintptr_t ptr, uintptr_t start, size_t size)
{
	uintptr_t end = start + size;

	return ptr >= end || ptr < start;
}

/* Check if pointed structure's end is out-of-bound */
static bool __ptr_struct_end_oob(uintptr_t ptr, size_t struct_size, uintptr_t start, size_t size)
{
	return __ptr_oob(ptr + struct_size - 1, start, size);
}

/* Check if pointed structure is out-of-bound */
static bool __ptr_struct_oob(uintptr_t ptr, size_t struct_size, uintptr_t start, size_t size)
{
	return __ptr_oob(ptr, start, size) || __ptr_struct_end_oob(ptr, struct_size, start, size);
}

/* Local strlen implementation */
static size_t __strlen(const char *str)
{
	const char *ptr;

	if (!str)
		return 0;

	ptr = str;
	while (*ptr != '\0')
		ptr++;

	return ptr - str;
}

/*
 * Elf hash, see format specification.
 */
static unsigned long elf_sysv_hash(const unsigned char *name)
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

/* * The GNU hash format. Taken from glibc.  */
static unsigned long elf_gnu_hash(const unsigned char *name)
{
	unsigned long h = 5381;
	for (unsigned char c = *name; c != '\0'; c = *++name)
		h = h * 33 + c;
	return h;
}

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BORD ELFDATA2MSB /* 0x02 */
#else
#define BORD ELFDATA2LSB /* 0x01 */
#endif

static int has_elf_identity(Ehdr_t *ehdr)
{
	/* check ELF magic */

	if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
	    ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
	    ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
	    ehdr->e_ident[EI_MAG3] != ELFMAG3) {
		pr_err("Invalid ELF magic\n");
		return false;
	};

	/* check ELF class */
#if defined(CONFIG_VDSO_32)
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS32) {
		pr_err("Unsupported ELF class: %d\n", ehdr->e_ident[EI_CLASS]);
		return false;
	};
#else
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
		pr_err("Unsupported ELF class: %d\n", ehdr->e_ident[EI_CLASS]);
		return false;
	};
#endif

	/* check ELF data encoding */
	if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
		pr_err("Unsupported ELF data encoding: %d\n", ehdr->e_ident[EI_DATA]);
		return false;
	};
	/* check ELF version */
	if (ehdr->e_ident[EI_VERSION] != EV_CURRENT) {
		pr_err("Unsupported ELF version: %d\n", ehdr->e_ident[EI_VERSION]);
		return false;
	};
	/* check ELF OSABI */
	if (ehdr->e_ident[EI_OSABI] != ELFOSABI_NONE &&
	    ehdr->e_ident[EI_OSABI] != ELFOSABI_LINUX) {
		pr_err("Unsupported OSABI version: %d\n", ehdr->e_ident[EI_OSABI]);
		return false;
	};

	return true;
}

static int parse_elf_phdr(uintptr_t mem, size_t size,
			  Phdr_t **dynamic, Phdr_t **load, bool *is_32bit)
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

	*is_32bit = ehdr->e_ident[EI_CLASS] != ELFCLASS64;

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
 *   @dyn_hash     - address of the symbol hash table
 *   @use_gnu_hash - the format of hash DT_HASH or DT_GNU_HASH
 */
static int parse_elf_dynamic(uintptr_t mem, size_t size, Phdr_t *dynamic,
			     Dyn_t **dyn_strtab, Dyn_t **dyn_symtab,
			     Dyn_t **dyn_hash, bool *use_gnu_hash)
{
	Dyn_t *dyn_gnu_hash = NULL, *dyn_sysv_hash = NULL;
	Dyn_t *dyn_syment = NULL;
	Dyn_t *dyn_strsz = NULL;
	uintptr_t addr;
	Dyn_t *d;
	int i;

	addr = mem + dynamic->p_offset;
	if (__ptr_oob(addr, mem, size))
		goto err_oob;

	for (i = 0; i < dynamic->p_filesz / sizeof(*d); i++, addr += sizeof(Dyn_t)) {
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
			dyn_sysv_hash = d;
			pr_debug("DT_HASH: %lx\n", (unsigned long)d->d_un.d_ptr);
		} else if (d->d_tag == DT_GNU_HASH) {
			/*
			 * This is complicated.
			 *
			 * Looking at the Linux kernel source, the following can be seen
			 * regarding which hashing style the VDSO uses on each arch:
			 *
			 *     aarch64: not specified (depends on linker, can be
			 *                             only GNU hash style)
			 *     arm: --hash-style=sysv
			 *     loongarch: --hash-style=sysv
			 *     mips: --hash-style=sysv
			 *     powerpc: --hash-style=both
			 *     riscv: --hash-style=both
			 *     s390: --hash-style=both
			 *     x86: --hash-style=both
			 *
			 * Some architectures are using both hash-styles, that
			 * is the easiest for CRIU. Some architectures are only
			 * using the old style (sysv), that is what CRIU supports.
			 *
			 * Starting with Linux 6.11, aarch64 unfortunately decided
			 * to switch from '--hash-style=sysv' to ''. Specifying
			 * nothing unfortunately may mean GNU hash style only and not
			 * 'both' (depending on the linker).
			 */
			dyn_gnu_hash = d;
			pr_debug("DT_GNU_HASH: %lx\n", (unsigned long)d->d_un.d_ptr);
		}
	}

	if (!*dyn_strtab || !*dyn_symtab || !dyn_strsz || !dyn_syment ||
	    (!dyn_gnu_hash && !dyn_sysv_hash)) {
		pr_err("Not all dynamic entries are present\n");
		return -EINVAL;
	}

	/*
	 * Prefer DT_HASH over DT_GNU_HASH as it's been more tested and
	 * as a result more stable.
	 */
	*use_gnu_hash = !dyn_sysv_hash;
	*dyn_hash = dyn_sysv_hash ?: dyn_gnu_hash;

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

typedef uint32_t Hash32_t;

static bool elf_symbol_match(uintptr_t mem, size_t size,
		uintptr_t dynsymbol_names, Sym_t *sym,
		const char *symbol, const size_t vdso_symbol_length)
{
	uintptr_t addr = (uintptr_t)sym;
	char *name;

	if (__ptr_struct_oob(addr, sizeof(Sym_t), mem, size))
		return false;

	if (ELF_ST_TYPE(sym->st_info) != STT_FUNC && ELF_ST_BIND(sym->st_info) != STB_GLOBAL)
		return false;

	addr = dynsymbol_names + sym->st_name;
	if (__ptr_struct_oob(addr, vdso_symbol_length, mem, size))
		return false;
	name = (void *)addr;

	return !std_strncmp(name, symbol, vdso_symbol_length);
}


static unsigned long elf_symbol_lookup(uintptr_t mem, size_t size,
		const char *symbol, uint32_t symbol_hash, unsigned int sym_off,
		uintptr_t dynsymbol_names, Dyn_t *dyn_symtab, Phdr_t *load,
		uint32_t nbucket, uint32_t nchain, void *_bucket, Hash_t *chain,
		const size_t vdso_symbol_length, bool use_gnu_hash)
{
	unsigned int j;
	uintptr_t addr;

	addr = mem + dyn_symtab->d_un.d_ptr - load->p_vaddr;

	if (use_gnu_hash) {
		Hash32_t *h, hash_val, *bucket = _bucket;

		j = bucket[symbol_hash % nbucket];
		if (j == STN_UNDEF)
			return 0;

		h = bucket + nbucket + (j - sym_off);

		symbol_hash |= 1;
		do {
			Sym_t *sym = (void *)addr + sizeof(Sym_t) * j;

			hash_val = *h++;
			if ((hash_val | 1) == symbol_hash &&
			    elf_symbol_match(mem, size, dynsymbol_names, sym,
					     symbol, vdso_symbol_length))
				return sym->st_value;
			j++;
		} while (!(hash_val & 1));
	} else {
		Hash_t *bucket = _bucket;

		j = bucket[symbol_hash % nbucket];
		if (j == STN_UNDEF)
			return 0;

		for (; j < nchain && j != STN_UNDEF; j = chain[j]) {
			Sym_t *sym = (void *)addr + sizeof(Sym_t) * j;

			if (elf_symbol_match(mem, size, dynsymbol_names, sym,
					     symbol, vdso_symbol_length))
				return sym->st_value;
		}
	}
	return 0;
}

static int parse_elf_symbols(uintptr_t mem, size_t size, Phdr_t *load,
			     struct vdso_symtable *t, uintptr_t dynsymbol_names,
			     Hash_t *hash, Dyn_t *dyn_symtab, bool use_gnu_hash,
			     bool is_32bit)
{
	ARCH_VDSO_SYMBOLS_LIST

	const char *vdso_symbols[VDSO_SYMBOL_MAX] = { ARCH_VDSO_SYMBOLS };
	const size_t vdso_symbol_length = sizeof(t->symbols[0].name) - 1;

	void *bucket = NULL;
	Hash_t *chain = NULL;
	uint32_t nbucket, nchain = 0;

	unsigned int sym_off = 0;
	unsigned int i = 0;

	unsigned long (*elf_hash)(const unsigned char *);

	if (use_gnu_hash) {
		uint32_t *gnu_hash = (uint32_t *)hash;
		uint32_t bloom_sz;

		nbucket = gnu_hash[0];
		sym_off = gnu_hash[1];
		bloom_sz = gnu_hash[2];
		if (is_32bit) {
			uint32_t *bloom;
			bloom = (uint32_t *)&gnu_hash[4];
			bucket = (Hash_t *)(&bloom[bloom_sz]);
		} else {
			uint64_t *bloom;
			bloom = (uint64_t *)&gnu_hash[4];
			bucket = (Hash_t *)(&bloom[bloom_sz]);
		}
		elf_hash = &elf_gnu_hash;
		pr_debug("nbucket %lx sym_off %lx bloom_sz %lx bucket %lx\n",
			 (unsigned long)nbucket, (unsigned long)sym_off,
			 (unsigned long)bloom_sz,
			 (unsigned long)bucket);
	} else {
		nbucket = hash[0];
		nchain = hash[1];
		bucket = &hash[2];
		chain = &hash[nbucket + 2];
		elf_hash = &elf_sysv_hash;
		pr_debug("nbucket %lx nchain %lx bucket %lx chain %lx\n",
			 (unsigned long)nbucket, (unsigned long)nchain,
			 (unsigned long)bucket, (unsigned long)chain);
	}


	for (i = 0; i < VDSO_SYMBOL_MAX; i++) {
		const char *symbol = vdso_symbols[i];
		unsigned long addr, symbol_hash;
		const size_t symbol_length = __strlen(symbol);

		symbol_hash = elf_hash((const unsigned char *)symbol);
		addr = elf_symbol_lookup(mem, size, symbol, symbol_hash,
				sym_off, dynsymbol_names, dyn_symtab, load,
				nbucket, nchain, bucket, chain,
				vdso_symbol_length, use_gnu_hash);
		pr_debug("symbol %s at address %lx\n", symbol, addr);
		if (!addr)
			continue;

		/* XXX: provide strncpy() implementation for PIE */
		if (symbol_length > vdso_symbol_length) {
			pr_err("strlen(%s) %zd, only %zd bytes available\n",
				symbol, symbol_length, vdso_symbol_length);
			return -EINVAL;
		}
		memcpy(t->symbols[i].name, symbol, symbol_length);
		t->symbols[i].offset = addr - load->p_vaddr;
	}

	return 0;
}

int vdso_fill_symtable(uintptr_t mem, size_t size, struct vdso_symtable *t)
{
	Phdr_t *dynamic = NULL, *load = NULL;
	Dyn_t *dyn_strtab = NULL;
	Dyn_t *dyn_symtab = NULL;
	Dyn_t *dyn_hash = NULL;
	Hash_t *hash = NULL;
	bool use_gnu_hash;
	bool is_32bit;

	uintptr_t dynsymbol_names;
	uintptr_t addr;
	int ret;

	pr_debug("Parsing at %lx %lx\n", (long)mem, (long)mem + (long)size);

	/*
	 * We need PT_LOAD and PT_DYNAMIC here. Each once.
	 */
	ret = parse_elf_phdr(mem, size, &dynamic, &load, &is_32bit);
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

	ret = parse_elf_dynamic(mem, size, dynamic, &dyn_strtab, &dyn_symtab,
				&dyn_hash, &use_gnu_hash);
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

	ret = parse_elf_symbols(mem, size, load, t, dynsymbol_names, hash, dyn_symtab,
				use_gnu_hash, is_32bit);

	if (ret <0)
		return ret;

	return 0;

err_oob:
	pr_err("Corrupted Elf symbols/hash\n");
	return -EFAULT;
}
