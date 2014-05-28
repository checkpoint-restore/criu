#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "asm/string.h"
#include "asm/types.h"

#include "compiler.h"
#include "syscall.h"
#include "vdso.h"
#include "vma.h"
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


/* Check if pointer is out-of-bound */
static bool __ptr_oob(void *ptr, void *start, size_t size)
{
	void *end = (void *)((unsigned long)start + size);
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

int vdso_fill_symtable(char *mem, size_t size, struct vdso_symtable *t)
{
	Elf64_Phdr *dynamic = NULL, *load = NULL;
	Elf64_Ehdr *ehdr = (void *)mem;
	Elf64_Dyn *dyn_strtab = NULL;
	Elf64_Dyn *dyn_symtab = NULL;
	Elf64_Dyn *dyn_strsz = NULL;
	Elf64_Dyn *dyn_syment = NULL;
	Elf64_Dyn *dyn_hash = NULL;
	Elf64_Word *hash = NULL;
	Elf64_Phdr *phdr;
	Elf64_Dyn *d;

	Elf64_Word *bucket, *chain;
	Elf64_Word nbucket, nchain;

	/*
	 * See Elf specification for this magic values.
	 */
	const char elf_ident[] = {
		0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};

	const char *vdso_symbols[VDSO_SYMBOL_MAX] = {
		[VDSO_SYMBOL_CLOCK_GETTIME]	= VDSO_SYMBOL_CLOCK_GETTIME_NAME,
		[VDSO_SYMBOL_GETCPU]		= VDSO_SYMBOL_GETCPU_NAME,
		[VDSO_SYMBOL_GETTIMEOFDAY]	= VDSO_SYMBOL_GETTIMEOFDAY_NAME,
		[VDSO_SYMBOL_TIME]		= VDSO_SYMBOL_TIME_NAME,
	};

	char *dynsymbol_names;
	unsigned int i, j, k;

	BUILD_BUG_ON(sizeof(elf_ident) != sizeof(ehdr->e_ident));

	pr_debug("Parsing at %lx %lx\n", (long)mem, (long)mem + (long)size);

	/*
	 * Make sure it's a file we support.
	 */
	if (builtin_memcmp(ehdr->e_ident, elf_ident, sizeof(elf_ident))) {
		pr_err("Elf header magic mismatch\n");
		return -EINVAL;
	}

	/*
	 * We need PT_LOAD and PT_DYNAMIC here. Each once.
	 */
	phdr = (void *)&mem[ehdr->e_phoff];
	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		if (__ptr_oob(phdr, mem, size))
			goto err_oob;
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
	d = (void *)&mem[dynamic->p_offset];
	for (i = 0; i < dynamic->p_filesz / sizeof(*d); i++, d++) {
		if (__ptr_oob(d, mem, size))
			goto err_oob;

		if (d->d_tag == DT_NULL) {
			break;
		} else if (d->d_tag == DT_STRTAB) {
			dyn_strtab = d;
			pr_debug("DT_STRTAB: %p\n", (void *)d->d_un.d_ptr);
		} else if (d->d_tag == DT_SYMTAB) {
			dyn_symtab = d;
			pr_debug("DT_SYMTAB: %p\n", (void *)d->d_un.d_ptr);
		} else if (d->d_tag == DT_STRSZ) {
			dyn_strsz = d;
			pr_debug("DT_STRSZ: %lu\n", (unsigned long)d->d_un.d_val);
		} else if (d->d_tag == DT_SYMENT) {
			dyn_syment = d;
			pr_debug("DT_SYMENT: %lu\n", (unsigned long)d->d_un.d_val);
		} else if (d->d_tag == DT_HASH) {
			dyn_hash = d;
			pr_debug("DT_HASH: %p\n", (void *)d->d_un.d_ptr);
		}
	}

	if (!dyn_strtab || !dyn_symtab || !dyn_strsz || !dyn_syment || !dyn_hash) {
		pr_err("Not all dynamic entries are present\n");
		return -EINVAL;
	}

	dynsymbol_names = &mem[dyn_strtab->d_un.d_val - load->p_vaddr];
	if (__ptr_oob(dynsymbol_names, mem, size))
		goto err_oob;

	hash = (void *)&mem[(unsigned long)dyn_hash->d_un.d_ptr - (unsigned long)load->p_vaddr];
	if (__ptr_oob(hash, mem, size))
		goto err_oob;

	nbucket = hash[0];
	nchain = hash[1];
	bucket = &hash[2];
	chain = &hash[nbucket + 2];

	pr_debug("nbucket %lu nchain %lu bucket %p chain %p\n",
		 (long)nbucket, (long)nchain, bucket, chain);

	for (i = 0; i < ARRAY_SIZE(vdso_symbols); i++) {
		k = elf_hash((const unsigned char *)vdso_symbols[i]);

		for (j = bucket[k % nbucket]; j < nchain && chain[j] != STN_UNDEF; j = chain[j]) {
			Elf64_Sym *sym = (void *)&mem[dyn_symtab->d_un.d_ptr - load->p_vaddr];
			char *name;

			sym = &sym[j];
			if (__ptr_oob(sym, mem, size))
				continue;

			if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC &&
			    ELF64_ST_BIND(sym->st_info) != STB_GLOBAL)
				continue;

			name = &dynsymbol_names[sym->st_name];
			if (__ptr_oob(name, mem, size))
				continue;

			if (builtin_strcmp(name, vdso_symbols[i]))
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
