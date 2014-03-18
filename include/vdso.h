#ifndef __CR_VDSO_H__
#define __CR_VDSO_H__

#include <sys/mman.h>
#include <stdbool.h>

#include "asm/vdso.h"
#include "asm/int.h"

#define VDSO_PROT		(PROT_READ | PROT_EXEC)


#define VDSO_BAD_ADDR		(-1ul)
#define VDSO_BAD_PFN		(-1ull)

struct vdso_symbol {
	char		name[32];
	unsigned long	offset;
};

#define VDSO_SYMBOL_INIT						\
	{ .offset = VDSO_BAD_ADDR, }

/* Check if symbol present in symtable */
static inline bool vdso_symbol_empty(struct vdso_symbol *s)
{
	return s->offset == VDSO_BAD_ADDR && s->name[0] == '\0';
}

struct vdso_symtable {
	unsigned long		vma_start;
	unsigned long		vma_end;
	struct vdso_symbol	symbols[VDSO_SYMBOL_MAX];
};

#define VDSO_SYMTABLE_INIT						\
	{								\
		.vma_start	= VDSO_BAD_ADDR,			\
		.vma_end	= VDSO_BAD_ADDR,			\
		.symbols		= {				\
			[0 ... VDSO_SYMBOL_MAX - 1] =			\
				(struct vdso_symbol)VDSO_SYMBOL_INIT,	\
			},						\
	}

#define VDSO_INIT_SYMTABLE(symtable)					\
	*(symtable) = (struct vdso_symtable)VDSO_SYMTABLE_INIT

/* Size of VMA associated with vdso */
static inline unsigned long vdso_vma_size(struct vdso_symtable *t)
{
	return t->vma_end - t->vma_start;
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
	unsigned long		proxy_addr;
};

/* Magic number (criuvdso) */
#define VDSO_MARK_SIGNATURE	(0x6f73647675697263ULL)

static inline bool is_vdso_mark(void *addr)
{
	struct vdso_mark *m = addr;

	return m->signature == VDSO_MARK_SIGNATURE &&
		m->proxy_addr != VDSO_BAD_ADDR;
}

static inline void vdso_put_mark(void *where, unsigned long proxy_addr)
{
	struct vdso_mark *m = where;

	m->signature = VDSO_MARK_SIGNATURE;
	m->proxy_addr = proxy_addr;
}

extern struct vdso_symtable vdso_sym_rt;
extern u64 vdso_pfn;
extern int vdso_init(void);
extern int vdso_remap(char *who, unsigned long from, unsigned long to, size_t size);
extern int vdso_fill_symtable(char *mem, size_t size, struct vdso_symtable *t);
extern int vdso_proxify(char *who, struct vdso_symtable *sym_rt, VmaEntry *vma_entry, unsigned long vdso_rt_parked_at);

#endif /* __CR_VDSO_H__ */
