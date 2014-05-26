#ifndef __CR_VDSO_H__
#define __CR_VDSO_H__

#include <sys/mman.h>
#include <stdbool.h>

#include "config.h"

#ifdef CONFIG_VDSO

#include "asm/vdso.h"

#else /* CONFIG_VDSO */

#define vdso_init()						(0)
#define parasite_fixup_vdso(ctl, pid, vma_area_list)		(0)
#define vdso_vma_size(t)					(0)
#define vdso_remap(who, from, to, size)				(0)
#define vdso_proxify(who, sym_rt, vma, vdso_rt_parked_at)	(0)

#endif /* CONFIG_VDSO */

#endif /* __CR_VDSO_H__ */
