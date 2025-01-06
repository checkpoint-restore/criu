#include <unistd.h>

#include "restorer.h"
#include "asm/restorer.h"

#include <compel/plugins/std/syscall.h>
#include "log.h"
#include <compel/asm/fpu.h>
#include "cpu.h"
#include "page.h"
#include "common/err.h"

int restore_nonsigframe_gpregs(UserArmRegsEntry *r)
{
	return 0;
}

/*
 * On ARMv6 CPUs with VIPT caches there are aliasing issues:
 * if two different cache line indexes correspond to the same physical
 * address, then changes made to one of the alias might be lost or they
 * can overwrite each other. To overcome aliasing issues, page coloring
 * with 4 pages align for shared mappings was introduced (SHMLBA) in kernel.
 * Which resulted in unique physical address after any tag in cache
 * (because two upper bits corresponding to page address get unused in tags).
 *
 * The problem here is in shmat() syscall:
 * 1. if shmaddr is NULL then do_shmat() uses arch_get_unmapped_area()
 *    to allocate shared mapping. Which checks if CPU cache is VIPT
 *    and only then use SHMLBA alignment.
 * 2. if shmaddr is specified then do_shmat() checks that address has
 *    SHMLBA alignment regardless to CPU cache aliasing.
 *
 * All above means that on non-VIPT CPU (like any ARMv7) we can get
 * non-SHMLBA, but page-aligned address with shmat(shmid, NULL, shmflg),
 * but we can't restore it with shmat(shmid, shmaddr, shmflg).
 * Which results that we can dump e.g., application with shmem aligned
 * on 2 pages, but can't restore it on the same ARMv7 CPU.
 *
 * To workaround this kernel feature, use mremap() on shmem mapping,
 * allocated with shmat(shmid, NULL, shmflg).
 */
#define SHMLBA (4UL * PAGE_SIZE)
unsigned long arch_shmat(int shmid, void *shmaddr, int shmflg, unsigned long size)
{
	unsigned long smap;

	/* SHMLBA-aligned, direct call shmat() */
	if (!((unsigned long)shmaddr & (SHMLBA - 1)))
		return sys_shmat(shmid, shmaddr, shmflg);

	smap = sys_shmat(shmid, NULL, shmflg);
	if (IS_ERR_VALUE(smap)) {
		pr_err("shmat() with NULL shmaddr failed: %d\n", (int)smap);
		return smap;
	}

	/* We're lucky! */
	if (smap == (unsigned long)shmaddr)
		return smap;

	/* Warn ALOUD */
	pr_warn("Restoring shmem %p unaligned to SHMLBA.\n", shmaddr);
	pr_warn("Make sure that you don't migrate shmem from non-VIPT cached CPU to VIPT cached (e.g., ARMv7 -> ARMv6)\n");
	pr_warn("Otherwise YOU HAVE A CHANCE OF DATA CORRUPTIONS in writeable shmem\n");

	smap = sys_mremap(smap, size, size, MREMAP_FIXED | MREMAP_MAYMOVE, (unsigned long)shmaddr);
	if (IS_ERR_VALUE(smap))
		pr_err("mremap() for shmem failed: %d\n", (int)smap);
	return smap;
}
