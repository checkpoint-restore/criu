#ifndef __CR_MMAN_H__
#define __CR_MMAN_H__

#ifndef MAP_HUGETLB
# define MAP_HUGETLB		0x40000
#endif
#ifndef MADV_HUGEPAGE
# define MADV_HUGEPAGE		14
#endif
#ifndef MADV_NOHUGEPAGE
# define MADV_NOHUGEPAGE	15
#endif
#ifndef MADV_DONTDUMP
# define MADV_DONTDUMP		16
#endif

#endif /* __CR_MMAN_H__ */
