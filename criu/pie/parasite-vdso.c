#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <elf.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "int.h"
#include "types.h"
#include "page.h"
#include "syscall.h"
#include "image.h"
#include "parasite-vdso.h"
#include "vma.h"
#include "log.h"
#include "common/bug.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif
#define LOG_PREFIX "vdso: "


static int vdso_remap(char *who, unsigned long from, unsigned long to, size_t size)
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

/* Park runtime vDSO in some safe place where it can be accessible from restorer */
int vdso_do_park(struct vdso_symtable *sym_rt, unsigned long park_at, unsigned long park_size)
{
	int ret;

	BUG_ON((vdso_vma_size(sym_rt) + vvar_vma_size(sym_rt)) < park_size);

	if (sym_rt->vvar_start != VDSO_BAD_ADDR) {
		if (sym_rt->vma_start < sym_rt->vvar_start) {
			ret  = vdso_remap("rt-vdso", sym_rt->vma_start,
					  park_at, vdso_vma_size(sym_rt));
			park_at += vdso_vma_size(sym_rt);
			ret |= vdso_remap("rt-vvar", sym_rt->vvar_start,
					  park_at, vvar_vma_size(sym_rt));
		} else {
			ret  = vdso_remap("rt-vvar", sym_rt->vvar_start,
					  park_at, vvar_vma_size(sym_rt));
			park_at += vvar_vma_size(sym_rt);
			ret |= vdso_remap("rt-vdso", sym_rt->vma_start,
					  park_at, vdso_vma_size(sym_rt));
		}
	} else
		ret = vdso_remap("rt-vdso", sym_rt->vma_start,
				 park_at, vdso_vma_size(sym_rt));
	return ret;
}

int vdso_proxify(char *who, struct vdso_symtable *sym_rt,
		 unsigned long vdso_rt_parked_at, size_t index,
		 VmaEntry *vmas, size_t nr_vmas)
{
	VmaEntry *vma_vdso = NULL, *vma_vvar = NULL;
	struct vdso_symtable s = VDSO_SYMTABLE_INIT;
	bool remap_rt = false;

	/*
	 * Figure out which kind of vdso tuple we get.
	 */
	if (vma_entry_is(&vmas[index], VMA_AREA_VDSO))
		vma_vdso = &vmas[index];
	else if (vma_entry_is(&vmas[index], VMA_AREA_VVAR))
		vma_vvar = &vmas[index];

	if (index < (nr_vmas - 1)) {
		if (vma_entry_is(&vmas[index + 1], VMA_AREA_VDSO))
			vma_vdso = &vmas[index + 1];
		else if (vma_entry_is(&vmas[index + 1], VMA_AREA_VVAR))
			vma_vvar = &vmas[index + 1];
	}

	if (!vma_vdso) {
		pr_err("Can't find vDSO area in image\n");
		return -1;
	}

	/*
	 * vDSO mark overwrites Elf program header of proxy vDSO thus
	 * it must never ever be greater in size.
	 */
	BUILD_BUG_ON(sizeof(struct vdso_mark) > sizeof(Elf64_Phdr));

	/*
	 * Find symbols in vDSO zone read from image.
	 */
	if (vdso_fill_symtable((uintptr_t)vma_vdso->start,
				vma_entry_len(vma_vdso), &s))
		return -1;

	/*
	 * Proxification strategy
	 *
	 *  - There might be two vDSO zones: vdso code and optionally vvar data
	 *  - To be able to use in-place remapping we need
	 *
	 *    a) Size and order of vDSO zones are to match
	 *    b) Symbols offsets must match
	 *    c) Have same number of vDSO zones
	 */
	if (vma_entry_len(vma_vdso) == vdso_vma_size(sym_rt)) {
		size_t i;

		for (i = 0; i < ARRAY_SIZE(s.symbols); i++) {
			if (s.symbols[i].offset != sym_rt->symbols[i].offset)
				break;
		}

		if (i == ARRAY_SIZE(s.symbols)) {
			if (vma_vvar && sym_rt->vvar_start != VVAR_BAD_ADDR) {
				remap_rt = (vvar_vma_size(sym_rt) == vma_entry_len(vma_vvar));
				if (remap_rt) {
					long delta_rt = sym_rt->vvar_start - sym_rt->vma_start;
					long delta_this = vma_vvar->start - vma_vdso->start;

					remap_rt = (delta_rt ^ delta_this) < 0 ? false : true;
				}
			} else
				remap_rt = true;
		}
	}

	pr_debug("image [vdso] %lx-%lx [vvar] %lx-%lx\n",
		 (unsigned long)vma_vdso->start, (unsigned long)vma_vdso->end,
		 vma_vvar ? (unsigned long)vma_vvar->start : VVAR_BAD_ADDR,
		 vma_vvar ? (unsigned long)vma_vvar->end : VVAR_BAD_ADDR);

	/*
	 * Easy case -- the vdso from image has same offsets, order and size
	 * as runtime, so we simply remap runtime vdso to dumpee position
	 * without generating any proxy.
	 *
	 * Note we may remap VVAR vdso as well which might not yet been mapped
	 * by a caller code. So drop VMA_AREA_REGULAR from it and caller would
	 * not touch it anymore.
	 */
	if (remap_rt) {
		int ret = 0;

		pr_info("Runtime vdso/vvar matches dumpee, remap inplace\n");

		if (sys_munmap((void *)(uintptr_t)vma_vdso->start,
					vma_entry_len(vma_vdso))) {
			pr_err("Failed to unmap %s\n", who);
			return -1;
		}

		if (vma_vvar) {
			if (sys_munmap((void *)(uintptr_t)vma_vvar->start,
						vma_entry_len(vma_vvar))) {
				pr_err("Failed to unmap %s\n", who);
				return -1;
			}

			if (vma_vdso->start < vma_vvar->start) {
				ret  = vdso_remap(who, vdso_rt_parked_at, vma_vdso->start, vdso_vma_size(sym_rt));
				vdso_rt_parked_at += vdso_vma_size(sym_rt);
				ret |= vdso_remap(who, vdso_rt_parked_at, vma_vvar->start, vvar_vma_size(sym_rt));
			} else {
				ret  = vdso_remap(who, vdso_rt_parked_at, vma_vvar->start, vvar_vma_size(sym_rt));
				vdso_rt_parked_at += vvar_vma_size(sym_rt);
				ret |= vdso_remap(who, vdso_rt_parked_at, vma_vdso->start, vdso_vma_size(sym_rt));
			}
		} else
			ret = vdso_remap(who, vdso_rt_parked_at, vma_vdso->start, vdso_vma_size(sym_rt));

		return ret;
	}

	/*
	 * Now complex case -- we need to proxify calls. We redirect
	 * calls from dumpee vdso to runtime vdso, making dumpee
	 * to operate as proxy vdso.
	 */
	pr_info("Runtime vdso mismatches dumpee, generate proxy\n");

	/*
	 * Don't forget to shift if vvar is before vdso.
	 */
	if (sym_rt->vvar_start != VDSO_BAD_ADDR &&
	    sym_rt->vvar_start < sym_rt->vma_start)
		vdso_rt_parked_at += vvar_vma_size(sym_rt);

	if (vdso_redirect_calls(vdso_rt_parked_at,
				vma_vdso->start,
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
	vdso_put_mark((void *)vdso_rt_parked_at, vma_vdso->start, vma_vvar ? vma_vvar->start : VVAR_BAD_ADDR);
	sys_mprotect((void *)vdso_rt_parked_at,  vdso_vma_size(sym_rt), VDSO_PROT);
	return 0;
}
