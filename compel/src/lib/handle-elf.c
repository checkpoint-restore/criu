#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "handle-elf.h"
#include "piegen.h"
#include "log.h"

#ifdef CONFIG_MIPS
#include "ldsodefs.h"
#endif
/* Check if pointer is out-of-bound */
static bool __ptr_oob(const uintptr_t ptr, const uintptr_t start, const size_t size)
{
	uintptr_t end = start + size;

	return ptr >= end || ptr < start;
}

/* Check if pointed structure's end is out-of-bound */
static bool __ptr_struct_end_oob(const uintptr_t ptr, const size_t struct_size,
				 const uintptr_t start, const size_t size)
{
	/* the last byte of the structure should be inside [begin, end) */
	return __ptr_oob(ptr + struct_size - 1, start, size);
}

/* Check if pointed structure is out-of-bound */
static bool __ptr_struct_oob(const uintptr_t ptr, const size_t struct_size,
			     const uintptr_t start, const size_t size)
{
	return __ptr_oob(ptr, start, size) ||
		__ptr_struct_end_oob(ptr, struct_size, start, size);
}

static bool test_pointer(const void *ptr, const void *start, const size_t size,
			 const char *name, const char *file, const int line)
{
	if (__ptr_oob((const uintptr_t)ptr, (const uintptr_t)start, size)) {
		pr_err("Corrupted pointer %p (%s) at %s:%d\n",
		       ptr, name, file, line);
		return true;
	}
	return false;
}

#define ptr_func_exit(__ptr)						\
	do {								\
		if (test_pointer((__ptr), mem, size, #__ptr,		\
				 __FILE__, __LINE__)) {			\
			free(sec_hdrs);					\
			return -1;					\
		}							\
	} while (0)

#ifdef ELF_PPC64
static int do_relative_toc(long value, uint16_t *location,
			   unsigned long mask, int complain_signed)
{
	if (complain_signed && (value + 0x8000 > 0xffff)) {
		pr_err("TOC16 relocation overflows (%ld)\n", value);
		return -1;
	}

	if ((~mask & 0xffff) & value) {
		pr_err("bad TOC16 relocation (%ld) (0x%lx)\n",
		       value, (~mask & 0xffff) & value);
		return -1;
	}

	*location = (*location & ~mask) | (value & mask);
	return 0;
}
#endif

static bool is_header_supported(Elf_Ehdr *hdr)
{
	if (!arch_is_machine_supported(hdr->e_machine))
		return false;
	if ((hdr->e_type != ET_REL
#ifdef NO_RELOCS
		&& hdr->e_type != ET_EXEC
#endif
	    ) || hdr->e_version != EV_CURRENT)
		return false;
	return true;
}

static const char *get_strings_section(Elf_Ehdr *hdr, uintptr_t mem, size_t size)
{
	size_t sec_table_size = ((size_t) hdr->e_shentsize) * hdr->e_shnum;
	uintptr_t sec_table = mem + hdr->e_shoff;
	Elf_Shdr *secstrings_hdr;
	uintptr_t addr;

	if (__ptr_struct_oob(sec_table, sec_table_size, mem, size)) {
		pr_err("Section table [%#zx, %#zx) is out of [%#zx, %#zx)\n",
			sec_table, sec_table + sec_table_size, mem, mem + size);
		return NULL;
	}

	/*
	 * strings section header's offset in section headers table is
	 * (size of section header * index of string section header)
	 */
	addr = sec_table + ((size_t) hdr->e_shentsize) * hdr->e_shstrndx;
	if (__ptr_struct_oob(addr, sizeof(Elf_Shdr),
			sec_table, sec_table_size)) {
		pr_err("String section header @%#zx is out of [%#zx, %#zx)\n",
			addr, sec_table, sec_table + sec_table_size);
		return NULL;
	}
	secstrings_hdr = (void*)addr;

	addr = mem + secstrings_hdr->sh_offset;
	if (__ptr_struct_oob(addr, secstrings_hdr->sh_size, mem, size)) {
		pr_err("String section @%#zx size %#lx is out of [%#zx, %#zx)\n",
			addr, (unsigned long)secstrings_hdr->sh_size,
			mem, mem + size);
		return NULL;
	}

	return (void*)addr;
}

/*
 * This name @__handle_elf get renamed into
 * @handle_elf_ppc64 or say @handle_elf_x86_64
 * depending on the architecture it's compiled
 * under.
 */
int __handle_elf(void *mem, size_t size)
{
	const char *symstrings = NULL;
	Elf_Shdr *symtab_hdr = NULL;
	Elf_Sym *symbols = NULL;
	Elf_Ehdr *hdr = mem;

	Elf_Shdr *strtab_hdr = NULL;
	Elf_Shdr **sec_hdrs = NULL;
	const char *secstrings;

	size_t i, k, nr_gotpcrel = 0;
#ifdef ELF_PPC64
	int64_t toc_offset = 0;
#endif
	int ret = -EINVAL;

	pr_debug("Header\n");
	pr_debug("------------\n");
	pr_debug("\ttype 0x%x machine 0x%x version 0x%x\n",
		 (unsigned)hdr->e_type, (unsigned)hdr->e_machine,
		 (unsigned)hdr->e_version);

	if (!is_header_supported(hdr)) {
		pr_err("Unsupported header detected\n");
		goto err;
	}

	sec_hdrs = malloc(sizeof(*sec_hdrs) * hdr->e_shnum);
	if (!sec_hdrs) {
		pr_err("No memory for section headers\n");
		ret = -ENOMEM;
		goto err;
	}

	secstrings = get_strings_section(hdr, (uintptr_t)mem, size);
	if (!secstrings)
		goto err;

	pr_debug("Sections\n");
	pr_debug("------------\n");
	for (i = 0; i < hdr->e_shnum; i++) {
		Elf_Shdr *sh = mem + hdr->e_shoff + hdr->e_shentsize * i;
		ptr_func_exit(sh);

		if (sh->sh_type == SHT_SYMTAB)
			symtab_hdr = sh;

		ptr_func_exit(&secstrings[sh->sh_name]);
		pr_debug("\t index %-2zd type 0x%-2x name %s\n", i,
			 (unsigned)sh->sh_type, &secstrings[sh->sh_name]);

		sec_hdrs[i] = sh;

#ifdef ELF_PPC64
		if (!strcmp(&secstrings[sh->sh_name], ".toc")) {
			toc_offset = sh->sh_addr + 0x8000;
			pr_debug("\t\tTOC offset 0x%lx\n", toc_offset);
		}
#endif
	}
        
	/* Calculate section addresses with proper alignment.
	 * Note: some but not all linkers precalculate this information.
	 */
	for (i = 0, k = 0; i < hdr->e_shnum; i++) {
		Elf_Shdr *sh = sec_hdrs[i];
		if (!(sh->sh_flags & SHF_ALLOC))
			continue;
		if (sh->sh_addralign > 0 && k % sh->sh_addralign != 0) {
			k += sh->sh_addralign - k % sh->sh_addralign;
		}
		if (sh->sh_addr && sh->sh_addr != k) {
			pr_err("Unexpected precalculated address of section (section %s addr 0x%lx expected 0x%lx)\n",
				   &secstrings[sh->sh_name],
				   (unsigned long) sh->sh_addr,
				   (unsigned long) k);
			goto err;
		}
		sh->sh_addr = k;
		k += sh->sh_size;
	}

	if (!symtab_hdr) {
		pr_err("No symbol table present\n");
		goto err;
	}

	if (!symtab_hdr->sh_link || symtab_hdr->sh_link >= hdr->e_shnum) {
		pr_err("Corrupted symtab header\n");
		goto err;
	}

	pr_debug("Symbols\n");
	pr_debug("------------\n");
	strtab_hdr = sec_hdrs[symtab_hdr->sh_link];
	ptr_func_exit(strtab_hdr);

	symbols = mem + symtab_hdr->sh_offset;
	ptr_func_exit(symbols);
	symstrings = mem + strtab_hdr->sh_offset;
	ptr_func_exit(symstrings);

	if (sizeof(*symbols) != symtab_hdr->sh_entsize) {
		pr_err("Symbol table align differ\n");
		goto err;
	}

	pr_out("/* Autogenerated from %s */\n", opts.input_filename);
	pr_out("#include <compel/infect.h>\n");

	for (i = 0; i < symtab_hdr->sh_size / symtab_hdr->sh_entsize; i++) {
		Elf_Sym *sym = &symbols[i];
		const char *name;
		Elf_Shdr *sh_src;

		ptr_func_exit(sym);
		name = &symstrings[sym->st_name];
		ptr_func_exit(name);

		if (!*name)
			continue;

		pr_debug("\ttype 0x%-2x bind 0x%-2x shndx 0x%-4x value 0x%-2lx name %s\n",
				(unsigned)ELF_ST_TYPE(sym->st_info), (unsigned)ELF_ST_BIND(sym->st_info),
				(unsigned)sym->st_shndx, (unsigned long)sym->st_value, name);
#ifdef ELF_PPC64
		if (!sym->st_value && !strncmp(name, ".TOC.", 6)) {
			if (!toc_offset) {
				pr_err("No TOC pointer\n");
				goto err;
			}
			sym->st_value = toc_offset;
			continue;
		}
#endif
		if (strncmp(name, "__export", 8))
			continue;
		if ((sym->st_shndx && sym->st_shndx < hdr->e_shnum) ||
				sym->st_shndx == SHN_ABS) {
			if (sym->st_shndx == SHN_ABS) {
				sh_src = NULL;
			} else {
				sh_src = sec_hdrs[sym->st_shndx];
				ptr_func_exit(sh_src);
			}
			pr_out("#define %s_sym%s 0x%lx\n",
					opts.prefix, name,
					(unsigned long)(sym->st_value +
						(sh_src ? sh_src->sh_addr : 0)));
		}
	}

	pr_out("static __maybe_unused compel_reloc_t %s_relocs[] = {\n", opts.prefix);
#ifndef NO_RELOCS
	pr_debug("Relocations\n");
	pr_debug("------------\n");
	for (i = 0; i < hdr->e_shnum; i++) {
		Elf_Shdr *sh = sec_hdrs[i];
		Elf_Shdr *sh_rel;

		if (sh->sh_type != SHT_REL && sh->sh_type != SHT_RELA)
			continue;

		sh_rel = sec_hdrs[sh->sh_info];
		ptr_func_exit(sh_rel);

		pr_debug("\tsection %2zd type 0x%-2x link 0x%-2x info 0x%-2x name %s\n", i,
			 (unsigned)sh->sh_type, (unsigned)sh->sh_link,
			 (unsigned)sh->sh_info, &secstrings[sh->sh_name]);

		for (k = 0; k < sh->sh_size / sh->sh_entsize; k++) {
			int64_t __maybe_unused addend64, __maybe_unused value64;
			int32_t __maybe_unused addend32, __maybe_unused value32;
			unsigned long place;
			const char *name;
			void *where;
			Elf_Sym *sym;

			union {
				Elf_Rel rel;
				Elf_Rela rela;
			} *r = mem + sh->sh_offset + sh->sh_entsize * k;
			ptr_func_exit(r);

			sym = &symbols[ELF_R_SYM(r->rel.r_info)];
			ptr_func_exit(sym);

			name = &symstrings[sym->st_name];
			ptr_func_exit(name);

			where = mem + sh_rel->sh_offset + r->rel.r_offset;
			ptr_func_exit(where);

			pr_debug("\t\tr_offset 0x%-4lx r_info 0x%-4lx / sym 0x%-2lx type 0x%-2lx symsecoff 0x%-4lx\n",
				 (unsigned long)r->rel.r_offset, (unsigned long)r->rel.r_info,
				 (unsigned long)ELF_R_SYM(r->rel.r_info),
				 (unsigned long)ELF_R_TYPE(r->rel.r_info),
				 (unsigned long)sh_rel->sh_addr);

			if (sym->st_shndx == SHN_UNDEF) {
#ifdef ELF_PPC64
				/* On PowerPC, TOC symbols appear to be
				 * undefined but should be processed as well.
				 * Their type is STT_NOTYPE, so report any
				 * other one.
				 */
				if (ELF32_ST_TYPE(sym->st_info) != STT_NOTYPE
				    || strncmp(name, ".TOC.", 6)) {
					pr_err("Unexpected undefined symbol:%s\n", name);
					goto err;
				}
#else
				pr_err("Unexpected undefined symbol: `%s'. External symbol in PIE?\n", name);
				goto err;
#endif
			} else if (sym->st_shndx == SHN_COMMON) {
				/*
				 * To support COMMON symbols, we could
				 * allocate these variables somewhere,
				 * perhaps somewhere near the GOT table.
				 * For now, we punt.
				 */
				pr_err("Unsupported COMMON symbol: `%s'. Try initializing the variable\n", name);
				goto err;
			}

			if (sh->sh_type == SHT_REL) {
				addend32 = *(int32_t *)where;
				addend64 = *(int64_t *)where;
			} else {
				addend32 = (int32_t)r->rela.r_addend;
				addend64 = (int64_t)r->rela.r_addend;
			}

			place = sh_rel->sh_addr + r->rel.r_offset;

			pr_debug("\t\t\tvalue 0x%-8lx addend32 %-4d addend64 %-8ld place %-8lx symname %s\n",
				 (unsigned long)sym->st_value, addend32, (long)addend64, (long)place, name);

			if (sym->st_shndx == SHN_ABS) {
				value32 = (int32_t)sym->st_value;
				value64 = (int64_t)sym->st_value;
			} else {
				Elf_Shdr *sh_src;

				if ((unsigned)sym->st_shndx > (unsigned)hdr->e_shnum) {
					pr_err("Unexpected symbol section index %u/%u\n",
					       (unsigned)sym->st_shndx, hdr->e_shnum);
					goto err;
				}
				sh_src = sec_hdrs[sym->st_shndx];
				ptr_func_exit(sh_src);

				value32 = (int32_t)sh_src->sh_addr + (int32_t)sym->st_value;
				value64 = (int64_t)sh_src->sh_addr + (int64_t)sym->st_value;
			}

#ifdef ELF_PPC64
/*
 * Snippet from the OpenPOWER ABI for Linux Supplement:
 *
 * The OpenPOWER ABI uses the three most-significant bits in the symbol
 * st_other field specifies the number of instructions between a function's
 * global entry point and local entry point. The global entry point is used
 * when it is necessary to set up the TOC pointer (r2) for the function. The
 * local entry point is used when r2 is known to already be valid for the
 * function. A value of zero in these bits asserts that the function does
 * not use r2.
 *
 * The st_other values have the following meanings:
 * 0 and 1, the local and global entry points are the same.
 * 2, the local entry point is at 1 instruction past the global entry point.
 * 3, the local entry point is at 2 instructions past the global entry point.
 * 4, the local entry point is at 4 instructions past the global entry point.
 * 5, the local entry point is at 8 instructions past the global entry point.
 * 6, the local entry point is at 16 instructions past the global entry point.
 * 7, reserved.
 *
 * Here we are only handle the case '3' which is the most commonly seen.
 */
#define LOCAL_OFFSET(s)	((s->st_other >> 5) & 0x7)
			if (LOCAL_OFFSET(sym)) {
				if (LOCAL_OFFSET(sym) != 3) {
					pr_err("Unexpected local offset value %d\n",
					       LOCAL_OFFSET(sym));
					goto err;
				}
				pr_debug("\t\t\tUsing local offset\n");
				value64 += 8;
				value32 += 8;
			}
#endif

			switch (ELF_R_TYPE(r->rel.r_info)) {
#ifdef CONFIG_MIPS
			case R_MIPS_PC16:
			      /* s+a-p relative */
			    *((int32_t *)where) = *((int32_t *)where) | ((value32 + addend32 - place)>>2);
			    break;

			case R_MIPS_26:
			      /*  local    : (((A << 2) | (P & 0xf0000000) + S) >> 2
			       *  external : (sign–extend(A < 2) + S) >> 2
                              */

			    if (((unsigned)ELF_ST_BIND(sym->st_info) == 0x1)
				 || ((unsigned)ELF_ST_BIND(sym->st_info) == 0x2)){
				  /* bind type local is 0x0 ,global is 0x1,WEAK is 0x2 */
				addend32 = value32;
			    }
			    pr_out("	{ .offset = 0x%-8x, .type = COMPEL_TYPE_MIPS_26,  "
			    	       ".addend = %-8d, .value = 0x%-16x, }, /* R_MIPS_26 */\n",
			    	       (unsigned int)place, addend32, value32);
			    break;

			case R_MIPS_32:
			    /* S+A */
			    break;

			case R_MIPS_64:
				pr_out("	{ .offset = 0x%-8x, .type = COMPEL_TYPE_MIPS_64, "
				       ".addend = %-8ld, .value = 0x%-16lx, }, /* R_MIPS_64 */\n",
				       (unsigned int)place, (long)addend64, (long)value64);
				break;

			case R_MIPS_HIGHEST:
			    pr_out("	{ .offset = 0x%-8x, .type = COMPEL_TYPE_MIPS_HIGHEST,  "
			    	       ".addend = %-8d, .value = 0x%-16x, }, /* R_MIPS_HIGHEST */\n",
			    	       (unsigned int)place, addend32, value32);
			    break;

			case R_MIPS_HIGHER:
			    pr_out("	{ .offset = 0x%-8x, .type = COMPEL_TYPE_MIPS_HIGHER,  "
			    	       ".addend = %-8d, .value = 0x%-16x, }, /* R_MIPS_HIGHER */\n",
			    	       (unsigned int)place, addend32, value32);
			    break;

			case R_MIPS_HI16:
			    pr_out("	{ .offset = 0x%-8x, .type = COMPEL_TYPE_MIPS_HI16,  "
			    	       ".addend = %-8d, .value = 0x%-16x, }, /* R_MIPS_HI16 */\n",
			    	       (unsigned int)place, addend32, value32);
			    break;

			case R_MIPS_LO16:
			    if((unsigned)ELF_ST_BIND(sym->st_info) == 0x1){
				  /* bind type local is 0x0 ,global is 0x1 */
				addend32 = value32;
			    }
			    pr_out("	{ .offset = 0x%-8x, .type = COMPEL_TYPE_MIPS_LO16,  "
			    	       ".addend = %-8d, .value = 0x%-16x, }, /* R_MIPS_LO16 */\n",
			    	       (unsigned int)place, addend32, value32);
			    break;

#endif
#ifdef ELF_PPC64
			case R_PPC64_REL24:
				/* Update PC relative offset, linker has not done this yet */
				pr_debug("\t\t\tR_PPC64_REL24 at 0x%-4lx val 0x%lx\n",
					 place, value64);
				/* Convert value to relative */
				value64 -= place;
				if (value64 + 0x2000000 > 0x3ffffff || (value64 & 3) != 0) {
					pr_err("REL24 %li out of range!\n", (long int)value64);
					goto err;
				}
				/* Only replace bits 2 through 26 */
				*(uint32_t *)where = (*(uint32_t *)where & ~0x03fffffc) |
					(value64 & 0x03fffffc);
				break;

			case R_PPC64_ADDR32:
			case R_PPC64_REL32:
				pr_debug("\t\t\tR_PPC64_ADDR32 at 0x%-4lx val 0x%x\n",
					 place, (unsigned int)(value32 + addend32));
				pr_out("	{ .offset = 0x%-8x, .type = COMPEL_TYPE_INT, "
				       " .addend = %-8d, .value = 0x%-16x, "
				       "}, /* R_PPC64_ADDR32 */\n",
				       (unsigned int) place,  addend32, value32);
				break;

			case R_PPC64_ADDR64:
			case R_PPC64_REL64:
				pr_debug("\t\t\tR_PPC64_ADDR64 at 0x%-4lx val 0x%lx\n",
					 place, value64 + addend64);
				pr_out("\t{ .offset = 0x%-8x, .type = COMPEL_TYPE_LONG,"
				       " .addend = %-8ld, .value = 0x%-16lx, "
				       "}, /* R_PPC64_ADDR64 */\n",
				       (unsigned int) place, (long)addend64, (long)value64);
				break;

			case R_PPC64_TOC16_HA:
				pr_debug("\t\t\tR_PPC64_TOC16_HA at 0x%-4lx val 0x%lx\n",
					 place, value64 + addend64 - toc_offset + 0x8000);
				if (do_relative_toc((value64 + addend64 - toc_offset + 0x8000) >> 16,
						    where, 0xffff, 1))
					goto err;
				break;

			case R_PPC64_TOC16_LO:
				pr_debug("\t\t\tR_PPC64_TOC16_LO at 0x%-4lx val 0x%lx\n",
					 place, value64 + addend64 - toc_offset);
				if (do_relative_toc(value64 + addend64 - toc_offset,
						    where, 0xffff, 1))
					goto err;
				break;

			case R_PPC64_TOC16_LO_DS:
				pr_debug("\t\t\tR_PPC64_TOC16_LO_DS at 0x%-4lx val 0x%lx\n",
					 place, value64 + addend64 - toc_offset);
				if (do_relative_toc(value64 + addend64 - toc_offset,
						    where, 0xfffc, 0))
					goto err;
				break;

			case R_PPC64_REL16_HA:
				value64 += addend64 - place;
				pr_debug("\t\t\tR_PPC64_REL16_HA at 0x%-4lx val 0x%lx\n",
					 place, value64);
				/* check that we are dealing with the addis 2,12 instruction */
				if (((*(uint32_t*)where) & 0xffff0000) != 0x3c4c0000) {
					pr_err("Unexpected instruction for R_PPC64_REL16_HA\n");
					goto err;
				}
				*(uint16_t *)where = ((value64 + 0x8000) >> 16) & 0xffff;
				break;

			case R_PPC64_REL16_LO:
				value64 += addend64 - place;
				pr_debug("\t\t\tR_PPC64_REL16_LO at 0x%-4lx val 0x%lx\n",
					 place, value64);
				/* check that we are dealing with the addi 2,2 instruction */
				if (((*(uint32_t*)where) & 0xffff0000) != 0x38420000) {
					pr_err("Unexpected instruction for R_PPC64_REL16_LO\n");
					goto err;
				}
				*(uint16_t *)where = value64 & 0xffff;
				break;

#endif /* ELF_PPC64 */

#ifdef ELF_X86_64
			case R_X86_64_32: /* Symbol + Addend (4 bytes) */
			case R_X86_64_32S: /* Symbol + Addend (4 bytes) */
				pr_debug("\t\t\t\tR_X86_64_32       at 0x%-4lx val 0x%x\n", place, value32);
				pr_out("	{ .offset = 0x%-8x, .type = COMPEL_TYPE_INT,  "
				       ".addend = %-8d, .value = 0x%-16x, }, /* R_X86_64_32 */\n",
				       (unsigned int)place, addend32, value32);
				break;
			case R_X86_64_64: /* Symbol + Addend (8 bytes) */
				pr_debug("\t\t\t\tR_X86_64_64       at 0x%-4lx val 0x%lx\n", place, (long)value64);
				pr_out("	{ .offset = 0x%-8x, .type = COMPEL_TYPE_LONG, "
				       ".addend = %-8ld, .value = 0x%-16lx, }, /* R_X86_64_64 */\n",
				       (unsigned int)place, (long)addend64, (long)value64);
				break;
			case R_X86_64_PC32: /* Symbol + Addend - Place (4 bytes) */
				pr_debug("\t\t\t\tR_X86_64_PC32     at 0x%-4lx val 0x%x\n", place, value32 + addend32 - (int32_t)place);
				/*
				 * R_X86_64_PC32 are relative, patch them inplace.
				 */
				*((int32_t *)where) = value32 + addend32 - place;
				break;
			case R_X86_64_PLT32: /* ProcLinkage + Addend - Place (4 bytes) */
				pr_debug("\t\t\t\tR_X86_64_PLT32    at 0x%-4lx val 0x%x\n", place, value32 + addend32 - (int32_t)place);
				/*
				 * R_X86_64_PLT32 are relative, patch them inplace.
				 */
				*((int32_t *)where) = value32 + addend32 - place;
				break;
			case R_X86_64_GOTPCRELX:
			case R_X86_64_REX_GOTPCRELX:
			case R_X86_64_GOTPCREL: /* SymbolOffsetInGot + GOT + Addend - Place  (4 bytes) */
				pr_debug("\t\t\t\tR_X86_64_GOTPCREL at 0x%-4lx val 0x%x\n", place, value32);
				pr_out("	{ .offset = 0x%-8x, .type = COMPEL_TYPE_LONG | COMPEL_TYPE_GOTPCREL, "
				       ".addend = %-8d, .value = 0x%-16x, }, /* R_X86_64_GOTPCREL */\n",
				       (unsigned int)place, addend32, value32);
				nr_gotpcrel++;
				break;
#endif

#ifdef ELF_X86_32
			case R_386_32: /* Symbol + Addend */
				pr_debug("\t\t\t\tR_386_32   at 0x%-4lx val 0x%x\n", place, value32 + addend32);
				pr_out("	{ .offset = 0x%-8x, .type = COMPEL_TYPE_INT,  "
				       ".addend = %-4d, .value = 0x%x, },\n",
				       (unsigned int)place, addend32, value32);
				break;
			case R_386_PC32: /* Symbol + Addend - Place */
				pr_debug("\t\t\t\tR_386_PC32 at 0x%-4lx val 0x%x\n", place, value32 + addend32 - (int32_t)place);
				/*
				 * R_386_PC32 are relative, patch them inplace.
				 */
				*((int32_t *)where) = value32 + addend32 - place;
				break;
#endif

#ifdef ELF_S390
			/*
			 * See also arch/s390/kernel/module.c/apply_rela():
			 * A PLT reads the GOT (global offest table). We can handle it like
			 * R_390_PC32DBL because we have linked statically.
			 */
			case R_390_PLT32DBL: /* PC relative on a PLT (predure link table) */
				pr_debug("\t\t\t\tR_390_PLT32DBL   at 0x%-4lx val 0x%x\n", place, value32 + addend32);
				*((int32_t *)where) = (value64 + addend64 - place) >> 1;
				break;
			case R_390_PC32DBL: /* PC relative on a symbol */
				pr_debug("\t\t\t\tR_390_PC32DBL    at 0x%-4lx val 0x%x\n", place, value32 + addend32);
				*((int32_t *)where) = (value64 + addend64 - place) >> 1;
				break;
			case R_390_64: /* 64 bit absolute address */
				pr_debug("\t\t\t\tR_390_64         at 0x%-4lx val 0x%lx\n", place, (long)value64);
				pr_out("	{ .offset = 0x%-8x, .type = COMPEL_TYPE_LONG, "
				       ".addend = %-8ld, .value = 0x%-16lx, }, /* R_390_64 */\n",
				       (unsigned int)place, (long)addend64, (long)value64);
				break;
			case R_390_PC64: /* 64 bit relative address */
				*((int64_t *)where) = value64 + addend64 - place;
				pr_debug("\t\t\t\tR_390_PC64       at 0x%-4lx val 0x%lx\n", place, (long)value64);
				break;
#endif
			default:
				pr_err("Unsupported relocation of type %lu\n",
					(unsigned long)ELF_R_TYPE(r->rel.r_info));
				goto err;
			}
		}
	}
#endif /* !NO_RELOCS */
	pr_out("};\n");

	pr_out("static __maybe_unused const char %s_blob[] = {\n\t", opts.prefix);

	for (i = 0, k = 0; i < hdr->e_shnum; i++) {
		Elf_Shdr *sh = sec_hdrs[i];
		unsigned char *shdata;
		size_t j;

		if (!(sh->sh_flags & SHF_ALLOC) || !sh->sh_size)
			continue;

		shdata =  mem + sh->sh_offset;
		pr_debug("Copying section '%s'\n"
			 "\tstart:0x%lx (gap:0x%lx) size:0x%lx\n",
			 &secstrings[sh->sh_name], (unsigned long) sh->sh_addr,
			 (unsigned long)(sh->sh_addr - k), (unsigned long) sh->sh_size);

		/* write 0 in the gap between the 2 sections */
		for (; k < sh->sh_addr; k++) {
			if (k && (k % 8) == 0)
				pr_out("\n\t");
			pr_out("0x00,");
		}

		for (j = 0; j < sh->sh_size; j++, k++) {
			if (k && (k % 8) == 0)
				pr_out("\n\t");
			pr_out("0x%02x,", shdata[j]);
		}
	}
	pr_out("};\n");
	pr_out("\n");
	pr_out("static void __maybe_unused %s_setup_c_header_desc(struct parasite_blob_desc *pbd, bool native)\n",
			opts.prefix);
	pr_out(
"{\n"
"	pbd->parasite_type	= COMPEL_BLOB_CHEADER;\n"
);
	pr_out("\tpbd->hdr.mem		= %s_blob;\n", opts.prefix);
	pr_out("\tpbd->hdr.bsize		= sizeof(%s_blob);\n",
			opts.prefix);
	pr_out("\tif (native)\n");
	pr_out("\t\tpbd->hdr.parasite_ip_off	= "
		"%s_sym__export_parasite_head_start;\n", opts.prefix);
	pr_out("#ifdef CONFIG_COMPAT\n");
	pr_out("\telse\n");
	pr_out("\t\tpbd->hdr.parasite_ip_off	= "
		"%s_sym__export_parasite_head_start_compat;\n", opts.prefix);
	pr_out("#endif /* CONFIG_COMPAT */\n");
	pr_out("\tpbd->hdr.cmd_off	= %s_sym__export_parasite_service_cmd;\n", opts.prefix);
	pr_out("\tpbd->hdr.args_ptr_off	= %s_sym__export_parasite_service_args_ptr;\n", opts.prefix);
	pr_out("\tpbd->hdr.got_off	= round_up(pbd->hdr.bsize, sizeof(long));\n");
	pr_out("\tpbd->hdr.args_off	= pbd->hdr.got_off + %zd*sizeof(long);\n", nr_gotpcrel);
	pr_out("\tpbd->hdr.relocs		= %s_relocs;\n", opts.prefix);
	pr_out("\tpbd->hdr.nr_relocs	= "
			"sizeof(%s_relocs) / sizeof(%s_relocs[0]);\n",
			opts.prefix, opts.prefix);
	pr_out("}\n");
	pr_out("\n");
	pr_out("static void __maybe_unused %s_setup_c_header(struct parasite_ctl *ctl)\n",
			opts.prefix);
	pr_out("{\n");
	pr_out("\t%s_setup_c_header_desc(compel_parasite_blob_desc(ctl), compel_mode_native(ctl));\n", opts.prefix);
	pr_out("}\n");

	ret = 0;
err:
	free(sec_hdrs);
	return ret;
}
