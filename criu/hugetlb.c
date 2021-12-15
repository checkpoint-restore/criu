#include "hugetlb.h"
#include "kerndat.h"
#include "sizes.h"

// clang-format off
struct htlb_info hugetlb_info[HUGETLB_MAX] = {
	[HUGETLB_16KB] = { SZ_16K, MAP_HUGETLB_16KB },
	[HUGETLB_64KB] = { SZ_64K, MAP_HUGETLB_64KB },
	[HUGETLB_512KB] = { SZ_512K, MAP_HUGETLB_512KB },
	[HUGETLB_1MB] = { SZ_1M, MAP_HUGETLB_1MB },
	[HUGETLB_2MB] = { SZ_2M, MAP_HUGETLB_2MB },
	[HUGETLB_8MB] = { SZ_8M, MAP_HUGETLB_8MB },
	[HUGETLB_16MB] = { SZ_16M, MAP_HUGETLB_16MB },
	[HUGETLB_32MB] = { SZ_32M, MAP_HUGETLB_32MB },
	[HUGETLB_256MB] = { SZ_256M, MAP_HUGETLB_256MB },
	[HUGETLB_512MB] = { SZ_512M, MAP_HUGETLB_512MB },
	[HUGETLB_1GB] = { SZ_1G, MAP_HUGETLB_1GB },
	[HUGETLB_2GB] = { SZ_2G, MAP_HUGETLB_2GB },
	[HUGETLB_16GB] = { SZ_16G, MAP_HUGETLB_16GB },
};
// clang-format on

int is_hugetlb_dev(dev_t dev, int *hugetlb_size_flag)
{
	int i;

	for (i = 0; i < HUGETLB_MAX; i++) {
		if (kdat.hugetlb_dev[i] == dev) {
			if (hugetlb_size_flag)
				*hugetlb_size_flag = hugetlb_info[i].flag;
			return 1;
		}
	}

	return 0;
}

unsigned long get_size_from_hugetlb_flag(int flag)
{
	int i;

	for (i = 0; i < HUGETLB_MAX; i++)
		if (flag == hugetlb_info[i].flag)
			return hugetlb_info[i].size;

	return -1;
}
