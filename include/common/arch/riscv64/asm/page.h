#ifndef __CR_ASM_PAGE_H__
#define __CR_ASM_PAGE_H__

#define ARCH_HAS_LONG_PAGES

#ifndef CR_NOGLIBC
#include <string.h> /* ffsl() */
#include <unistd.h> /* _SC_PAGESIZE */

extern unsigned __page_size;
extern unsigned __page_shift;

static inline unsigned page_size(void)
{
	if (!__page_size)
		__page_size = sysconf(_SC_PAGESIZE);
	return __page_size;
}

static inline unsigned page_shift(void)
{
	if (!__page_shift)
		__page_shift = (ffsl(page_size()) - 1);
	return __page_shift;
}

/*
 * Don't add ifdefs for PAGE_SIZE: if any header defines it as a constant
 * on aarch64, then we need refrain using PAGE_SIZE in criu and use
 * page_size() across sources (as it may differ on aarch64).
 */
#define PAGE_SIZE  page_size()
#define PAGE_MASK  (~(PAGE_SIZE - 1))
#define PAGE_SHIFT page_shift()

#define PAGE_PFN(addr) ((addr) / PAGE_SIZE)

#else /* CR_NOGLIBC */

extern unsigned page_size(void);
#define PAGE_SIZE page_size()

#endif /* CR_NOGLIBC */
#endif /* __CR_ASM_PAGE_H__ */
