#ifndef __CR_PARASITE_VDSO_H__
#define __CR_PARASITE_VDSO_H__

#include "common/config.h"
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
 * Special mark which allows to identify runtime vdso (rt-vdso) where
 * calls from proxy (original) vdso are redirected. This mark usually
 * placed at the start of vdso area where Elf header lives.
 * Since such runtime vdso is solely used by the proxy and
 * nobody else is supposed to access it, it's more-less
 * safe to screw the Elf header with @signature and
 * vvar/vdso addresses for next dumping.
 *
 * The @orig_addr deserves a few comments. When we redirect the calls
 * from the original vdso to runtime vdso, on next checkpoint it won't
 * be possible to find original vdso/vvar pair, thus we save their
 * addresses in the member.
 *
 * As on the following dumps we need to drop rt-{vvar,vdso} pair
 * from list of VMAs to save in images, we save rt-vvar address also.
 */
struct vdso_mark {
	u64 signature;
	unsigned long orig_vdso_addr;
	unsigned long version;
	unsigned long orig_vvar_addr;
	unsigned long rt_vvar_addr;
};

#define VDSO_MARK_SIGNATURE_V1 (0x6f73647675697263ULL) /* Magic number (criuvdso) */
#define VDSO_MARK_SIGNATURE_V2 (0x4f53447675697263ULL) /* Magic number (criuvDSO) */
#define VDSO_MARK_SIGNATURE_V3 (0x4f53447655495243ULL) /* Magic number (CRIUvDSO) */
#define VDSO_MARK_CUR_VERSION  (3)

static inline void vdso_put_mark(void *where, unsigned long rt_vvar_addr, unsigned long orig_vdso_addr,
				 unsigned long orig_vvar_addr)
{
	struct vdso_mark *m = where;

	m->signature = VDSO_MARK_SIGNATURE_V3;
	m->orig_vdso_addr = orig_vdso_addr;
	m->version = VDSO_MARK_CUR_VERSION;
	m->orig_vvar_addr = orig_vvar_addr;
	m->rt_vvar_addr = rt_vvar_addr;
}

static inline bool is_vdso_mark(void *addr)
{
	struct vdso_mark *m = addr;

	switch (m->signature) {
	case VDSO_MARK_SIGNATURE_V3:
		return true;
	/*
	 * Old formats -- simply extend the mark up
	 * to the version we support.
	 */
	case VDSO_MARK_SIGNATURE_V2:
		vdso_put_mark(m, VVAR_BAD_ADDR, m->orig_vdso_addr, m->orig_vvar_addr);
		return true;

	case VDSO_MARK_SIGNATURE_V1:
		vdso_put_mark(m, VVAR_BAD_ADDR, m->orig_vdso_addr, VVAR_BAD_ADDR);
		return true;
	}

	return false;
}

extern void vdso_update_gtod_addr(struct vdso_maps *rt);
extern int vdso_do_park(struct vdso_maps *rt, unsigned long park_at, unsigned long park_size);
extern int vdso_map_compat(unsigned long map_at);
extern int vdso_proxify(struct vdso_maps *rt, bool *added_proxy, VmaEntry *vmas, size_t nr_vmas, bool compat_vdso,
			bool force_trampolines);
extern int vdso_redirect_calls(unsigned long base_to, unsigned long base_from, struct vdso_symtable *to,
			       struct vdso_symtable *from, bool compat_vdso);

#endif /* __CR_PARASITE_VDSO_H__ */
