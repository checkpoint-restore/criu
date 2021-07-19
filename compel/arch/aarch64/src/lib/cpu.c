#include <string.h>
#include <stdbool.h>

#include "compel-cpu.h"

#include "common/bitops.h"

#include "log.h"

#undef LOG_PREFIX
#define LOG_PREFIX "cpu: "

static compel_cpuinfo_t rt_info;

static void fetch_rt_cpuinfo(void)
{
	static bool rt_info_done = false;

	if (!rt_info_done) {
		compel_cpuid(&rt_info);
		rt_info_done = true;
	}
}

void compel_set_cpu_cap(compel_cpuinfo_t *info, unsigned int feature)
{
}
void compel_clear_cpu_cap(compel_cpuinfo_t *info, unsigned int feature)
{
}
int compel_test_cpu_cap(compel_cpuinfo_t *info, unsigned int feature)
{
	return 0;
}
int compel_test_fpu_cap(compel_cpuinfo_t *info, unsigned int feature)
{
	return 0;
}
int compel_cpuid(compel_cpuinfo_t *info)
{
	return 0;
}

bool compel_cpu_has_feature(unsigned int feature)
{
	fetch_rt_cpuinfo();
	return compel_test_cpu_cap(&rt_info, feature);
}

bool compel_fpu_has_feature(unsigned int feature)
{
	fetch_rt_cpuinfo();
	return compel_test_fpu_cap(&rt_info, feature);
}

uint32_t compel_fpu_feature_size(unsigned int feature)
{
	fetch_rt_cpuinfo();
	return 0;
}

uint32_t compel_fpu_feature_offset(unsigned int feature)
{
	fetch_rt_cpuinfo();
	return 0;
}

void compel_cpu_clear_feature(unsigned int feature)
{
	fetch_rt_cpuinfo();
	return compel_clear_cpu_cap(&rt_info, feature);
}

void compel_cpu_copy_cpuinfo(compel_cpuinfo_t *c)
{
	fetch_rt_cpuinfo();
	memcpy(c, &rt_info, sizeof(rt_info));
}
