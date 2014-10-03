#undef	LOG_PREFIX
#define LOG_PREFIX "cpu: "

#include <errno.h>
#include "cpu.h"

bool cpu_has_feature(unsigned int feature)
{
	return false;
}

int cpu_init(void)
{
	return 0;
}

int cpu_dump_cpuinfo(void)
{
	return 0;
}

int cpu_validate_cpuinfo(void)
{
	return 0;
}

int cpu_dump_cpuinfo_single(void)
{
	return -ENOTSUP;
}

int cpu_validate_image_cpuinfo_single(void)
{
	return -ENOTSUP;
}

int cpuinfo_dump(void)
{
	return -ENOTSUP;
}

int cpuinfo_check(void)
{
	return -ENOTSUP;
}
