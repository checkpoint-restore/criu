#ifndef __CR_ASM_VDSO_H__
#define __CR_ASM_VDSO_H__

#include <sys/types.h>

#include "asm/int.h"
#include "protobuf/vma.pb-c.h"

struct parasite_ctl;
struct vm_area_list;

#define VDSO_PROT		(PROT_READ | PROT_EXEC)
#define VVAR_PROT		(PROT_READ)

#define VDSO_BAD_ADDR		(-1ul)
#define VVAR_BAD_ADDR		VDSO_BAD_ADDR
#define VDSO_BAD_PFN		(-1ull)
#define VVAR_BAD_PFN		VDSO_BAD_PFN

struct vdso_symbol {
	char			name[32];
	unsigned long		offset;
};

#define VDSO_SYMBOL_INIT	{ .offset = VDSO_BAD_ADDR, }

/* Check if symbol present in symtable */
static inline bool vdso_symbol_empty(struct vdso_symbol *s)
{
	return s->offset == VDSO_BAD_ADDR && s->name[0] == '\0';
}

/*
 * Pick from kernel file arch/powerpc/kernel/vdso64/vdso64.lds.S
 *
 * Note that '__kernel_datapage_offset' is not a service but mostly a data
 * inside the text page which should not be used as is from user space.
 */
enum {
	VDSO_SYMBOL_CLOCK_GETRES,
	VDSO_SYMBOL_CLOCK_GETTIME,
	VDSO_SYMBOL_GET_SYSCALL_MAP,
	VDSO_SYMBOL_GET_TBFREQ,
	VDSO_SYMBOL_GETCPU,
	VDSO_SYMBOL_GETTIMEOFDAY,
	VDSO_SYMBOL_SIGTRAMP_RT64,
	VDSO_SYMBOL_SYNC_DICACHE,
	VDSO_SYMBOL_SYNC_DICACHE_P5,
	VDSO_SYMBOL_TIME,

	VDSO_SYMBOL_MAX
};

#define VDSO_SYMBOL_CLOCK_GETRES_NAME		"__kernel_clock_getres"
#define VDSO_SYMBOL_CLOCK_GETTIME_NAME		"__kernel_clock_gettime"
#define VDSO_SYMBOL_GET_SYSCALL_MAP_NAME 	"__kernel_get_syscall_map"
#define VDSO_SYMBOL_GET_TBFREQ_NAME		"__kernel_get_tbfreq"
#define VDSO_SYMBOL_GETCPU_NAME			"__kernel_getcpu"
#define VDSO_SYMBOL_GETTIMEOFDAY_NAME		"__kernel_gettimeofday"
#define VDSO_SYMBOL_SIGTRAMP_RT64_NAME		"__kernel_sigtramp_rt64"
#define VDSO_SYMBOL_SYNC_DICACHE_NAME		"__kernel_sync_dicache"
#define VDSO_SYMBOL_SYNC_DICACHE_P5_NAME	"__kernel_sync_dicache_p5"
#define VDSO_SYMBOL_TIME_NAME			"__kernel_time"

struct vdso_symtable {
	unsigned long		vma_start;
	unsigned long		vma_end;
	unsigned long		vvar_start;
	unsigned long		vvar_end;
	struct vdso_symbol	symbols[VDSO_SYMBOL_MAX];
};

#define VDSO_SYMTABLE_INIT						\
	{								\
		.vma_start	= VDSO_BAD_ADDR,			\
		.vma_end	= VDSO_BAD_ADDR,			\
		.vvar_start	= VVAR_BAD_ADDR,			\
		.vvar_end	= VVAR_BAD_ADDR,			\
		.symbols		= {				\
			[0 ... VDSO_SYMBOL_MAX - 1] =			\
				(struct vdso_symbol)VDSO_SYMBOL_INIT,	\
			},						\
	}

/* Size of VMA associated with vdso */
static inline unsigned long vdso_vma_size(struct vdso_symtable *t)
{
	return t->vma_end - t->vma_start;
}

static inline unsigned long vvar_vma_size(struct vdso_symtable *t)
{
	return t->vvar_end - t->vvar_start;
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


extern struct vdso_symtable vdso_sym_rt;
extern u64 vdso_pfn;

extern int vdso_init(void);
extern int vdso_do_park(struct vdso_symtable *sym_rt, unsigned long park_at, unsigned long park_size);
extern int vdso_fill_symtable(char *mem, size_t size, struct vdso_symtable *t);
extern int vdso_proxify(char *who, struct vdso_symtable *sym_rt,
			unsigned long vdso_rt_parked_at, size_t index,
			VmaEntry *vmas, size_t nr_vmas);

extern int parasite_fixup_vdso(struct parasite_ctl *ctl, pid_t pid,
			       struct vm_area_list *vma_area_list);
extern void write_intraprocedure_branch(void *to, void *from);

#endif /* __CR_ASM_VDSO_H__ */
