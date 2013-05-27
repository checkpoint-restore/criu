#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "asm/string.h"
#include "asm/types.h"

#include "compiler.h"
#include "crtools.h"
#include "vdso.h"
#include "log.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif
#define LOG_PREFIX "vdso: "

typedef struct {
	u16	movabs;
	u64	imm64;
	u16	jmp_rax;
	u32	guards;
} __packed jmp_t;

int vdso_redirect_calls(void *base_to, void *base_from,
			struct vdso_symtable *to,
			struct vdso_symtable *from)
{
	jmp_t jmp = {
		.movabs		= 0xb848,
		.jmp_rax	= 0xe0ff,
		.guards		= 0xcccccccc,
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(to->symbols); i++) {
		if (vdso_symbol_empty(&from->symbols[i]))
			continue;

		pr_debug("jmp: %lx/%lx -> %lx/%lx (index %d)\n",
			 (unsigned long)base_from, from->symbols[i].offset,
			 (unsigned long)base_to, to->symbols[i].offset, i);

		jmp.imm64 = (unsigned long)base_to + to->symbols[i].offset;
		builtin_memcpy((void *)(base_from + from->symbols[i].offset), &jmp, sizeof(jmp));
	}

	return 0;
}

static unsigned int get_symbol_index(char *symbol, char *symbols[], size_t size)
{
	unsigned int i;

	for (i = 0; symbol && i < size; i++) {
		if (!builtin_strcmp(symbol, symbols[i]))
			return i;
	}

	return VDSO_SYMBOL_MAX;
}

/* Check if pointer is out-of-bound */
static bool __ptr_oob(void *ptr, void *start, size_t size)
{
	void *end = (void *)((unsigned long)start + size);
	return ptr > end || ptr < start;
}

int vdso_fill_symtable(char *mem, size_t size, struct vdso_symtable *t)
{
	Elf64_Ehdr *ehdr = (void *)mem;
	Elf64_Shdr *shdr, *shdr_strtab;
	Elf64_Shdr *shdr_dynsym;
	Elf64_Shdr *shdr_dynstr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *text;
	Elf64_Sym *sym;

	char *section_names, *dynsymbol_names;

	unsigned long base = VDSO_BAD_ADDR;
	unsigned int i, j, k;

	/*
	 * Elf header bytes. For detailed
	 * description see Elf specification.
	 */
	char vdso_ident[] = {
		0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};

	char *vdso_x86_symbols[VDSO_SYMBOL_MAX] = {
		[VDSO_SYMBOL_GETTIMEOFDAY]	= VDSO_SYMBOL_GETTIMEOFDAY_NAME,
		[VDSO_SYMBOL_GETCPU]		= VDSO_SYMBOL_GETCPU_NAME,
		[VDSO_SYMBOL_CLOCK_GETTIME]	= VDSO_SYMBOL_CLOCK_GETTIME_NAME,
		[VDSO_SYMBOL_TIME]		= VDSO_SYMBOL_TIME_NAME,
	};

	BUILD_BUG_ON(sizeof(vdso_ident) != sizeof(ehdr->e_ident));

	pr_debug("Parsing at %lx %lx\n",
		 (long)mem, (long)mem + (long)size);

	/*
	 * Make sure it's a file we support.
	 */
	if (builtin_memcmp(ehdr->e_ident, vdso_ident, sizeof(vdso_ident))) {
		pr_debug("Elf header magic mismatch\n");
		goto err;
	}

	/*
	 * Figure out base virtual address.
	 */
	phdr = (void *)&mem[ehdr->e_phoff];
	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		if (__ptr_oob(phdr, mem, size))
			goto err;
		if (phdr->p_type == PT_LOAD) {
			base = phdr->p_vaddr;
			break;
		}
	}
	if (base != VDSO_BAD_ADDR) {
		pr_debug("Base address %lx\n", base);
	} else {
		pr_debug("No base address found\n");
		goto err;
	}

	/*
	 * Where the section names lays.
	 */
	if (ehdr->e_shstrndx == SHN_UNDEF) {
		pr_err("Section names are not found\n");
		goto err;
	}

	shdr = (void *)&mem[ehdr->e_shoff];
	shdr_strtab = &shdr[ehdr->e_shstrndx];
	if (__ptr_oob(shdr_strtab, mem, size))
		goto err;

	section_names = (void *)&mem[shdr_strtab->sh_offset];
	shdr_dynsym = shdr_dynstr = text = NULL;

	for (i = 0; i < ehdr->e_shnum; i++, shdr++) {
		if (__ptr_oob(shdr, mem, size))
			goto err;
		if (__ptr_oob(&section_names[shdr->sh_name], mem, size))
			goto err;

#if 0
		pr_debug("section: %2d -> %s\n",
			 i, &section_names[shdr->sh_name]);
#endif

		if (shdr->sh_type == SHT_DYNSYM &&
		    builtin_strcmp(&section_names[shdr->sh_name],
				   ".dynsym") == 0) {
			shdr_dynsym = shdr;
		} else if (shdr->sh_type == SHT_STRTAB &&
			   builtin_strcmp(&section_names[shdr->sh_name],
					  ".dynstr") == 0) {
			shdr_dynstr = shdr;
		} else if (shdr->sh_type == SHT_PROGBITS &&
			   builtin_strcmp(&section_names[shdr->sh_name],
					  ".text") == 0) {
			text = shdr;
		}
	}

	if (!shdr_dynsym || !shdr_dynstr || !text) {
		pr_debug("No required sections found\n");
		goto err;
	}

	dynsymbol_names = (void *)&mem[shdr_dynstr->sh_offset];
	if (__ptr_oob(dynsymbol_names, mem, size)	||
	    __ptr_oob(shdr_dynsym, mem, size)		||
	    __ptr_oob(text, mem, size))
		goto err;

	/*
	 * Walk over global symbols and choose ones we need.
	 */
	j = shdr_dynsym->sh_size / sizeof(*sym);
	sym = (void *)&mem[shdr_dynsym->sh_offset];

	for (i = 0; i < j; i++, sym++) {
		if (__ptr_oob(sym, mem, size))
			goto err;

		if (ELF64_ST_BIND(sym->st_info) != STB_GLOBAL ||
		    ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
			continue;

		if (__ptr_oob(&dynsymbol_names[sym->st_name], mem, size))
			goto err;

		k = get_symbol_index(&dynsymbol_names[sym->st_name],
				     vdso_x86_symbols,
				     ARRAY_SIZE(vdso_x86_symbols));
		if (k != VDSO_SYMBOL_MAX) {
			builtin_memcpy(t->symbols[k].name, vdso_x86_symbols[k],
				       sizeof(t->symbols[k].name));
			t->symbols[k].offset = (unsigned long)sym->st_value - base;
#if 0
			pr_debug("symbol: %#-16lx %2d %s\n",
				 t->symbols[k].offset, sym->st_shndx, t->symbols[k].name);
#endif
		}
	}
	return 0;
err:
	return -1;
}

int vdso_remap(char *who, unsigned long from, unsigned long to, size_t size)
{
	unsigned long addr;

	pr_debug("Remap %s %lx -> %lx\n", who, from, to);

	addr = sys_mremap(from, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, to);
	if (addr != to) {
		pr_err("Unable to remap %lx -> %lx %lx\n",
		       from, to, addr);
		return -1;
	}

	return 0;
}

int vdso_proxify(char *who, struct vdso_symtable *sym_rt, VmaEntry *vma, unsigned long vdso_rt_parked_at)
{
	struct vdso_symtable s = VDSO_SYMTABLE_INIT;
	size_t size = vma_entry_len(vma);
	bool remap_rt = true;

	/*
	 * Find symbols in dumpee vdso.
	 */
	if (vdso_fill_symtable((void *)vma->start, size, &s))
		return -1;

	if (size == vdso_vma_size(sym_rt)) {
		int i;

		for (i = 0; i < ARRAY_SIZE(s.symbols); i++) {
			if (s.symbols[i].offset != sym_rt->symbols[i].offset) {
				remap_rt = false;
				break;
			}
		}
	} else
		remap_rt = false;

	/*
	 * Easy case -- the vdso from image has same offsets and size
	 * as runtime, so we simply remap runtime vdso to dumpee position
	 * without generating any proxy.
	 */
	if (remap_rt) {
		pr_info("Runtime vdso matches dumpee, remap inplace\n");

		if (sys_munmap((void *)vma->start, size)) {
			pr_err("Failed to unmap %s\n", who);
			return -1;
		}

		return vdso_remap(who, vdso_rt_parked_at, vma->start, size);
	}

	/*
	 * Now complex case -- we need to proxify calls. We redirect
	 * calls from dumpee vdso to runtime vdso, making dumpee
	 * to operate as proxy vdso.
	 */
	pr_info("Runtime vdso mismatches dumpee, generate proxy\n");

	if (vdso_redirect_calls((void *)vdso_rt_parked_at,
				(void *)vma->start,
				sym_rt, &s)) {
		pr_err("Failed to proxify dumpee contents\n");
		return -1;
	}

	/*
	 * Put a special mark into runtime vdso, thus at next checkpoint
	 * routine we could detect this vdso and do not dump it, since
	 * it's auto-generated every new session if proxy required.
	 */
	sys_mprotect((void *)vdso_rt_parked_at,  vdso_vma_size(sym_rt), PROT_WRITE);
	vdso_put_mark((void *)vdso_rt_parked_at, vma->start);
	sys_mprotect((void *)vdso_rt_parked_at,  vdso_vma_size(sym_rt), VDSO_PROT);
	return 0;
}
