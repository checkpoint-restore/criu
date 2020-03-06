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
#include "compel/plugins/std/syscall.h"
#include "compel/plugins/std/log.h"
#include "image.h"
#include "parasite-vdso.h"
#include "vma.h"
#include "log.h"
#include "common/bug.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif
#define LOG_PREFIX "vdso: "

/* Updates @from on success */
static int remap_one(char *who, unsigned long *from, unsigned long to, size_t size)
{
	unsigned long addr;

	pr_debug("Remap %s %lx -> %lx\n", who, *from, to);

	addr = sys_mremap(*from, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, to);
	if (addr != to) {
		pr_err("Unable to remap %lx -> %lx %lx\n", *from, to, addr);
		return -1;
	}
	*from = addr;

	return 0;
}

static int park_at(struct vdso_maps *rt, unsigned long vdso, unsigned long vvar)
{
	unsigned long vvar_size = rt->sym.vvar_size;
	unsigned long vdso_size = rt->sym.vdso_size;
	int ret;

	ret = remap_one("rt-vdso", &rt->vdso_start, vdso, vdso_size);
	if (ret)
		return ret;

	std_log_set_gettimeofday(NULL); /* stop using vdso for timings */

	if (vvar)
		ret = remap_one("rt-vvar", &rt->vvar_start, vvar, vvar_size);

	if (!ret)
		vdso_update_gtod_addr(rt);

	return ret;
}

void vdso_update_gtod_addr(struct vdso_maps *rt)
{
	struct vdso_symbol *gtod_sym;
	void *gtod;

	if (rt->vdso_start == VDSO_BAD_ADDR) {
		pr_debug("No rt-vdso - no fast gettimeofday()\n");
		return;
	}

	if (VDSO_SYMBOL_GTOD < 0) {
		pr_debug("Arch doesn't support gettimeofday() from vdso\n");
		return;
	}

	/*
	 * XXX: Don't enable vdso timings for compatible applications.
	 * We would need to temporary map 64-bit vdso for timings in restorer
	 * and remap it with compatible at the end of restore.
	 * And vdso proxification should be done much later.
	 * Also, restorer should have two sets of vdso_maps in arguments.
	 */
	if (rt->compatible) {
		pr_debug("compat mode: using syscall for gettimeofday()\n");
		return;
	}

	gtod_sym = &rt->sym.symbols[VDSO_SYMBOL_GTOD];
	if (gtod_sym->offset == VDSO_BAD_ADDR) {
		pr_debug("No gettimeofday() on rt-vdso\n");
		return;
	}

	gtod = (void*)(rt->vdso_start + gtod_sym->offset);
	pr_info("Using gettimeofday() on vdso at %p\n", gtod);

	std_log_set_gettimeofday(gtod);
}

/*
 * Park runtime vDSO in some safe place where it can be accessible
 * from the restorer
 */
int vdso_do_park(struct vdso_maps *rt, unsigned long addr, unsigned long space)
{
	unsigned long vvar_size = rt->sym.vvar_size;
	unsigned long vdso_size = rt->sym.vdso_size;

	if (rt->vvar_start == VVAR_BAD_ADDR) {
		BUG_ON(vdso_size < space);
		return park_at(rt, addr, 0);
	}

	BUG_ON((vdso_size + vvar_size) < space);

	if (rt->sym.vdso_before_vvar)
		return park_at(rt, addr, addr + vdso_size);
	else
		return park_at(rt, addr + vvar_size, addr);
}

#ifndef CONFIG_COMPAT
static int __vdso_fill_symtable(uintptr_t mem, size_t size,
		struct vdso_symtable *t, bool __always_unused compat_vdso)
{
	return vdso_fill_symtable(mem, size, t);
}
#endif

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
static bool blobs_matches(VmaEntry *vdso_img, VmaEntry *vvar_img,
		struct vdso_symtable *sym_img, struct vdso_symtable *sym_rt)
{
	unsigned long vdso_size = vma_entry_len(vdso_img);
	unsigned long rt_vdso_size = sym_rt->vdso_size;
	size_t i;

	if (vdso_size != rt_vdso_size) {
		pr_info("size differs: %lx != %lx (rt)\n",
			vdso_size, rt_vdso_size);
		return false;
	}

	for (i = 0; i < ARRAY_SIZE(sym_img->symbols); i++) {
		unsigned long sym_offset	= sym_img->symbols[i].offset;
		unsigned long rt_sym_offset	= sym_rt->symbols[i].offset;
		char *sym_name			= sym_img->symbols[i].name;

		if (sym_offset != rt_sym_offset) {
			pr_info("[%zu]`%s` offset differs: %lx != %lx (rt)\n",
				i, sym_name, sym_offset, rt_sym_offset);
			return false;
		}
	}

	if (vvar_img && sym_rt->vvar_size != VVAR_BAD_SIZE) {
		bool vdso_firstly = (vvar_img->start > vdso_img->start);
		unsigned long vvar_size = vma_entry_len(vvar_img);
		unsigned long rt_vvar_size = sym_rt->vvar_size;

		if (vvar_size != rt_vvar_size) {
			pr_info("vvar size differs: %lx != %lx (rt)\n",
				vdso_size, rt_vdso_size);
			return false;
		}

		if (vdso_firstly != sym_rt->vdso_before_vvar) {
			pr_info("[%s] pair has different order\n",
				vdso_firstly ? "vdso/vvar" : "vvar/vdso");
			return false;
		}
	}

	return true;
}

/*
 * The easy case -- the vdso from an image has the same offsets,
 * order and size as runtime vdso, so we simply remap runtime vdso
 * to dumpee position without generating any proxy.
 */
static int remap_rt_vdso(VmaEntry *vma_vdso, VmaEntry *vma_vvar,
			 struct vdso_maps *rt)
{
	void *remap_addr;

	pr_info("Runtime vdso/vvar matches dumpee, remap inplace\n");

	/*
	 * Ugly casts for 32bit platforms, which don't like uint64_t
	 * cast to (void *)
	 */
	remap_addr = (void *)(uintptr_t)vma_vdso->start;
	if (sys_munmap(remap_addr, vma_entry_len(vma_vdso))) {
		pr_err("Failed to unmap dumpee vdso\n");
		return -1;
	}

	if (!vma_vvar)
		return park_at(rt, vma_vdso->start, 0);

	remap_addr = (void *)(uintptr_t)vma_vvar->start;
	if (sys_munmap(remap_addr, vma_entry_len(vma_vvar))) {
		pr_err("Failed to unmap dumpee vvar\n");
		return -1;
	}

	return park_at(rt, vma_vdso->start, vma_vvar->start);
}

/*
 * The complex case -- we need to proxify calls. We redirect
 * calls from dumpee vdso to runtime vdso, making dumpee
 * to operate as proxy vdso.
 */
static int add_vdso_proxy(VmaEntry *vma_vdso, VmaEntry *vma_vvar,
		struct vdso_symtable *sym_img, struct vdso_maps *rt,
		bool compat_vdso)
{
	unsigned long orig_vvar_addr =
		vma_vvar ? vma_vvar->start : VVAR_BAD_ADDR;

	pr_info("Runtime vdso mismatches dumpee, generate proxy\n");

	/*
	 * Note: we assume that after first migration with inserted
	 * rt-vdso and trampoilines on the following migrations
	 * number of vdso symbols will not decrease.
	 * We don't save the content of original vdso under inserted
	 * jumps, so we can't remove them if on the following migration
	 * found that number of symbols in vdso has decreased.
	 */
	if (vdso_redirect_calls(rt->vdso_start, vma_vdso->start,
				&rt->sym, sym_img, compat_vdso)) {
		pr_err("Failed to proxify dumpee contents\n");
		return -1;
	}

	/*
	 * Put a special mark into runtime vdso, thus at next checkpoint
	 * routine we could detect this vdso and do not dump it, since
	 * it's auto-generated every new session if proxy required.
	 */
	sys_mprotect((void *)rt->vdso_start, rt->sym.vdso_size, PROT_WRITE);
	vdso_put_mark((void *)rt->vdso_start, rt->vvar_start,
		      vma_vdso->start, orig_vvar_addr);
	sys_mprotect((void *)rt->vdso_start, rt->sym.vdso_size, VDSO_PROT);

	return 0;
}

int vdso_proxify(struct vdso_maps *rt, bool *added_proxy,
		 VmaEntry *vmas, size_t nr_vmas,
		 bool compat_vdso, bool force_trampolines)
{
	VmaEntry *vma_vdso = NULL, *vma_vvar = NULL;
	struct vdso_symtable s = VDSO_SYMTABLE_INIT;
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
		 * We don't have to unmap rt-vdso, rt-vvar as we didn't
		 * park them previously.
		 */
		return 0;
	}

	if (!vma_vdso) {
		pr_err("Can't find vDSO area in image\n");
		return -1;
	}

	/*
	 * We could still do something about it here..
	 * 1. Hope that vDSO from images still works (might not be the case).
	 * 2. Try to map vDSO.
	 * But, hopefully no one intends to migrate application that uses
	 * vDSO to a dut where kernel doesn't provide it.
	 */
	if (!vdso_is_present(rt)) {
		pr_err("vDSO isn't provided by kernel, but exists in images\n");
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

	pr_debug("image [vdso] %lx-%lx [vvar] %lx-%lx\n",
		 (unsigned long)vma_vdso->start, (unsigned long)vma_vdso->end,
		 vma_vvar ? (unsigned long)vma_vvar->start : VVAR_BAD_ADDR,
		 vma_vvar ? (unsigned long)vma_vvar->end : VVAR_BAD_ADDR);

	*added_proxy = false;
	if (blobs_matches(vma_vdso, vma_vvar, &s, &rt->sym) && !force_trampolines)
		return remap_rt_vdso(vma_vdso, vma_vvar, rt);

	*added_proxy = true;
	return add_vdso_proxy(vma_vdso, vma_vvar, &s, rt, compat_vdso);
}
