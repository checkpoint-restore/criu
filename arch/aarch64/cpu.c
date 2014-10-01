#undef	LOG_PREFIX
#define LOG_PREFIX "cpu: "

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
