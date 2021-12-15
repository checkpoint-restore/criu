#ifndef __CR_HUGETLB_H_
#define __CR_HUGETLB_H_

#include <sys/types.h>
#include <stddef.h>

enum hugepage_size {
	HUGETLB_16KB,
	HUGETLB_64KB,
	HUGETLB_512KB,
	HUGETLB_1MB,
	HUGETLB_2MB,
	HUGETLB_8MB,
	HUGETLB_16MB,
	HUGETLB_32MB,
	HUGETLB_256MB,
	HUGETLB_512MB,
	HUGETLB_1GB,
	HUGETLB_2GB,
	HUGETLB_16GB,
	HUGETLB_MAX
};

#define MAP_HUGETLB_SHIFT     26
#define MAP_HUGETLB_SIZE_MASK (0x3f << MAP_HUGETLB_SHIFT)

#define MAP_HUGETLB_16KB  (14 << MAP_HUGETLB_SHIFT)
#define MAP_HUGETLB_64KB  (16 << MAP_HUGETLB_SHIFT)
#define MAP_HUGETLB_512KB (19 << MAP_HUGETLB_SHIFT)
#define MAP_HUGETLB_1MB	  (20 << MAP_HUGETLB_SHIFT)
#define MAP_HUGETLB_2MB	  (21 << MAP_HUGETLB_SHIFT)
#define MAP_HUGETLB_8MB	  (23 << MAP_HUGETLB_SHIFT)
#define MAP_HUGETLB_16MB  (24 << MAP_HUGETLB_SHIFT)
#define MAP_HUGETLB_32MB  (25 << MAP_HUGETLB_SHIFT)
#define MAP_HUGETLB_256MB (28 << MAP_HUGETLB_SHIFT)
#define MAP_HUGETLB_512MB (29 << MAP_HUGETLB_SHIFT)
#define MAP_HUGETLB_1GB	  (30 << MAP_HUGETLB_SHIFT)
#define MAP_HUGETLB_2GB	  (31 << MAP_HUGETLB_SHIFT)
#define MAP_HUGETLB_16GB  (34 << MAP_HUGETLB_SHIFT)

struct htlb_info {
	unsigned long long size;
	int flag;
};

extern struct htlb_info hugetlb_info[HUGETLB_MAX];

int is_hugetlb_dev(dev_t dev, int *hugetlb_size_flag);
unsigned long get_size_from_hugetlb_flag(int flag);

#ifndef MFD_HUGETLB
#define MFD_HUGETLB 4
#endif

#endif
