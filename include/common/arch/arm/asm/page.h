#ifndef __CR_ASM_PAGE_H__
#define __CR_ASM_PAGE_H__

#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#endif

#ifndef PAGE_MASK
#define PAGE_MASK (~(PAGE_SIZE - 1))
#endif

#define PAGE_PFN(addr) ((addr) / PAGE_SIZE)
#define page_size()    PAGE_SIZE

#endif /* __CR_ASM_PAGE_H__ */
