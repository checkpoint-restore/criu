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
#include <compel/plugins/std/syscall.h>
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

#if defined(CONFIG_X86_64) && defined(CONFIG_COMPAT)
int vdso_map_compat(unsigned long map_at)
{
	int ret;

	pr_debug("Mapping compatible vDSO at %lx\n", map_at);

	ret = sys_arch_prctl(ARCH_MAP_VDSO_32, map_at);
	if (ret < 0)
		return ret;
	return 0;
}

int __vdso_fill_symtable(uintptr_t mem, size_t size,
		struct vdso_symtable *t, bool compat_vdso)
{
	if (compat_vdso)
		return vdso_fill_symtable_compat(mem, size, t);
	else
		return vdso_fill_symtable(mem, size, t);
}
#else
int vdso_map_compat(unsigned long __always_unused map_at)
{
	/* shouldn't be called on !CONFIG_COMPAT */
	BUG();
	return 0;
}
int __vdso_fill_symtable(uintptr_t mem, size_t size,
		struct vdso_symtable *t, bool __always_unused compat_vdso)
{
	return vdso_fill_symtable(mem, size, t);
}
#endif

int vdso_proxify(struct vdso_symtable *sym_rt, unsigned long vdso_rt_parked_at,
		 VmaEntry *vmas, size_t nr_vmas,
		 bool compat_vdso, bool force_trampolines)
{
	VmaEntry *vma_vdso = NULL, *vma_vvar = NULL;
	struct vdso_symtable s = VDSO_SYMTABLE_INIT;
	bool remap_rt = false;
	unsigned int i;

	for (i = 0; i < nr_vmas; i++) {
		if (vma_entry_is(&vmas[i], VMA_AREA_VDSO))
			vma_vdso = &vmas[i];
		else if (vma_entry_is(&vmas[i], VMA_AREA_VVAR))
			vma_vvar = &vmas[i];
	}

	if (!vma_vdso && !vma_vvar) {
		pr_info("No VVAR, no vDSO in image\n");
		/*
		 * We don't have to unmap rt-vdso, rt-vvar as they will
		 * be unmapped with restorer blob in the end,
		 * see __export_unmap()
		 */
		return 0;
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
	if (__vdso_fill_symtable((uintptr_t)vma_vdso->start,
			vma_entry_len(vma_vdso), &s, compat_vdso))
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
	if (remap_rt && !force_trampolines) {
		int ret = 0;

		pr_info("Runtime vdso/vvar matches dumpee, remap inplace\n");

		if (sys_munmap((void *)(uintptr_t)vma_vdso->start,
					vma_entry_len(vma_vdso))) {
			pr_err("Failed to unmap dumpee\n");
			return -1;
		}

		if (vma_vvar) {
			if (sys_munmap((void *)(uintptr_t)vma_vvar->start,
						vma_entry_len(vma_vvar))) {
				pr_err("Failed to unmap dumpee\n");
				return -1;
			}

			if (vma_vdso->start < vma_vvar->start) {
				ret  = vdso_remap("rt-vdso", vdso_rt_parked_at, vma_vdso->start, vdso_vma_size(sym_rt));
				vdso_rt_parked_at += vdso_vma_size(sym_rt);
				ret |= vdso_remap("rt-vvar", vdso_rt_parked_at, vma_vvar->start, vvar_vma_size(sym_rt));
			} else {
				ret  = vdso_remap("rt-vvar", vdso_rt_parked_at, vma_vvar->start, vvar_vma_size(sym_rt));
				vdso_rt_parked_at += vvar_vma_size(sym_rt);
				ret |= vdso_remap("rt-vdso", vdso_rt_parked_at, vma_vdso->start, vdso_vma_size(sym_rt));
			}
		} else
			ret = vdso_remap("rt-vdso", vdso_rt_parked_at, vma_vdso->start, vdso_vma_size(sym_rt));

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
				sym_rt, &s, compat_vdso)) {
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
