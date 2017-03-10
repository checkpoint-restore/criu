#ifndef __CR_PARASITE_VDSO_H__
#define __CR_PARASITE_VDSO_H__

#include "config.h"

#ifdef CONFIG_VDSO

#include "util-vdso.h"
#include "images/vma.pb-c.h"

struct parasite_ctl;
struct vm_area_list;

/* Check if symbol present in symtable */
static inline bool vdso_symbol_empty(struct vdso_symbol *s)
{
	return s->offset == VDSO_BAD_ADDR && s->name[0] == '\0';
}

/*
 * Special mark which allows to identify runtime vdso where
 * calls from proxy vdso are redirected. This mark usually
 * placed at the start of vdso area where Elf header lives.
 * Since such runtime vdso is solevey used by proxy and
 * nobody else is supposed to access it, it's more-less
 * safe to screw the Elf header with @signature and
 * @proxy_addr.
 *
 * The @proxy_addr deserves a few comments. When we redirect
 * the calls from proxy to runtime vdso, on next checkpoint
 * it won't be possible to find which VMA is proxy, thus
 * we save its address in the member.
 */
struct vdso_mark {
	u64			signature;
	unsigned long		proxy_vdso_addr;

	unsigned long		version;

	/*
	 * In case of new vDSO format the VVAR area address
	 * neeed for easier discovering where it lives without
	 * relying on procfs output.
	 */
	unsigned long		proxy_vvar_addr;
};

#define VDSO_MARK_SIGNATURE	(0x6f73647675697263ULL)	/* Magic number (criuvdso) */
#define VDSO_MARK_SIGNATURE_V2	(0x4f53447675697263ULL)	/* Magic number (criuvDSO) */
#define VDSO_MARK_CUR_VERSION	(2)

static inline void vdso_put_mark(void *where, unsigned long proxy_vdso_addr, unsigned long proxy_vvar_addr)
{
	struct vdso_mark *m = where;

	m->signature		= VDSO_MARK_SIGNATURE_V2;
	m->proxy_vdso_addr	= proxy_vdso_addr;
	m->version		= VDSO_MARK_CUR_VERSION;
	m->proxy_vvar_addr	= proxy_vvar_addr;
}

static inline bool is_vdso_mark(void *addr)
{
	struct vdso_mark *m = addr;

	if (m->signature == VDSO_MARK_SIGNATURE_V2) {
		/*
		 * New format
		 */
		return true;
	} else if (m->signature == VDSO_MARK_SIGNATURE) {
		/*
		 * Old format -- simply extend the mark up
		 * to the version we support.
		 */
		vdso_put_mark(m, m->proxy_vdso_addr, VVAR_BAD_ADDR);
		return true;
	}
	return false;
}

extern int vdso_do_park(struct vdso_symtable *sym_rt, unsigned long park_at, unsigned long park_size);
extern int vdso_map_compat(unsigned long map_at);
extern int vdso_proxify(struct vdso_symtable *sym_rt,
			unsigned long vdso_rt_parked_at,
			VmaEntry *vmas, size_t nr_vmas,
			bool compat_vdso, bool force_trampolines);
extern int vdso_redirect_calls(unsigned long base_to, unsigned long base_from,
			struct vdso_symtable *to, struct vdso_symtable *from,
			bool compat_vdso);

#else /* CONFIG_VDSO */
#define vdso_do_park(sym_rt, park_at, park_size)		(0)
#define vdso_map_compat(map_at)					(0)

#endif /* CONFIG_VDSO */

#endif /* __CR_PARASITE_VDSO_H__ */
