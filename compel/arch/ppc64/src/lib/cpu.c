#include <sys/auxv.h>
#include <asm/cputable.h>
#include <errno.h>
#include <stdbool.h>

#include "compel-cpu.h"

#include "common/bitops.h"

#include "log.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "cpu: "

static compel_cpuinfo_t rt_info;
static bool rt_info_done = false;

void compel_set_cpu_cap(compel_cpuinfo_t *info, unsigned int feature) { }
void compel_clear_cpu_cap(compel_cpuinfo_t *info, unsigned int feature) { }
int compel_test_cpu_cap(compel_cpuinfo_t *info, unsigned int feature) { return 0; }

int compel_cpuid(compel_cpuinfo_t *info)
{
	info->hwcap[0] = getauxval(AT_HWCAP);
	info->hwcap[1] = getauxval(AT_HWCAP2);

	if (!info->hwcap[0] || !info->hwcap[1]) {
		pr_err("Can't read the hardware capabilities\n");
		return -1;
	}

	return 0;
}

bool compel_cpu_has_feature(unsigned int feature)
{
	if (!rt_info_done) {
		compel_cpuid(&rt_info);
		rt_info_done = true;
	}
	return compel_test_cpu_cap(&rt_info, feature);
}
