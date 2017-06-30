#undef	LOG_PREFIX
#define LOG_PREFIX "cpu: "

#include <sys/auxv.h>
#include <errno.h>

#include "asm/types.h"

#include "cr_options.h"
#include "image.h"
#include "util.h"
#include "log.h"
#include "cpu.h"

#include "protobuf.h"
#include "images/cpuinfo.pb-c.h"

static compel_cpuinfo_t rt_cpuinfo;

static const char *hwcap_str1[64] = {
	"HWCAP_S390_ESAN3",
	"HWCAP_S390_ZARCH",
	"HWCAP_S390_STFLE",
	"HWCAP_S390_MSA",
	"HWCAP_S390_LDISP",
	"HWCAP_S390_EIMM",
	"HWCAP_S390_DFP",
	"HWCAP_S390_HPAGE",
	"HWCAP_S390_ETF3EH",
	"HWCAP_S390_HIGH_GPRS",
	"HWCAP_S390_TE",
	"HWCAP_S390_VXRS",
	"HWCAP_S390_VXRS_BCD",
	"HWCAP_S390_VXRS_EXT",
};
static const char *hwcap_str2[64] = { };

static const char **hwcap_str[2] = { hwcap_str1, hwcap_str2 };

static void print_hwcaps(const char *msg, unsigned long hwcap[2])
{
	int nr, cap;

	pr_debug("%s: Capabilities: %016lx %016lx\n", msg, hwcap[0], hwcap[1]);
	for (nr = 0; nr < 2; nr++) {
		for (cap = 0; cap < 64; cap++) {
			if (!(hwcap[nr] & (1 << cap)))
				continue;
			if (hwcap_str[nr][cap])
				pr_debug("%s\n", hwcap_str[nr][cap]);
			else
				pr_debug("Capability %d/0x%x\n", nr, 1 << cap);
		}
	}
}

int cpu_init(void)
{
	int ret;

	ret = compel_cpuid(&rt_cpuinfo);
	print_hwcaps("Host (init)", rt_cpuinfo.hwcap);
	return ret;
}

int cpu_dump_cpuinfo(void)
{
	CpuinfoS390Entry cpu_s390_info = CPUINFO_S390_ENTRY__INIT;
	CpuinfoS390Entry *cpu_s390_info_ptr = &cpu_s390_info;
	CpuinfoEntry cpu_info = CPUINFO_ENTRY__INIT;
	struct cr_img *img;
	int ret = -1;

	img = open_image(CR_FD_CPUINFO, O_DUMP);
	if (!img)
	return -1;

	cpu_info.s390_entry = &cpu_s390_info_ptr;
	cpu_info.n_s390_entry = 1;

	cpu_s390_info.n_hwcap = 2;
	cpu_s390_info.hwcap = rt_cpuinfo.hwcap;

	ret = pb_write_one(img, &cpu_info, PB_CPUINFO);

	close_image(img);
	return ret;
}

int cpu_validate_cpuinfo(void)
{
	CpuinfoS390Entry *cpu_s390_entry;
	CpuinfoEntry *cpu_info;
	struct cr_img *img;
	int cap, nr, ret;

	img = open_image(CR_FD_CPUINFO, O_RSTR);
	if (!img)
		return -1;

	ret = 0;
	if (pb_read_one(img, &cpu_info, PB_CPUINFO) < 0)
		goto error;

	if (cpu_info->n_s390_entry != 1) {
		pr_err("No S390 related entry in image");
		goto error;
	}
	cpu_s390_entry = cpu_info->s390_entry[0];

	if (cpu_s390_entry->n_hwcap != 2) {
		pr_err("Hardware capabilities information missing\n");
		ret = -1;
		goto error;
	}

	print_hwcaps("Host", rt_cpuinfo.hwcap);
	print_hwcaps("Image", cpu_s390_entry->hwcap);

	for (nr = 0; nr < 2; nr++) {
		for (cap = 0; cap < 64; cap++) {
			if (!(cpu_s390_entry->hwcap[nr] & (1 << cap)))
				continue;
			if (rt_cpuinfo.hwcap[nr] & (1 << cap))
				continue;
			if (hwcap_str[nr][cap])
				pr_err("CPU Feature %s not supported on host\n",
				       hwcap_str[nr][cap]);
			else
				pr_err("CPU Feature %d/%x not supported on host\n",
				       nr, 1 << cap);
			ret = -1;
		}
	}
	if (ret == -1)
		pr_err("See also: /usr/include/bits/hwcap.h\n");
error:
	close_image(img);
	return ret;
}

int cpuinfo_dump(void)
{
	if (cpu_init())
		return -1;
	if (cpu_dump_cpuinfo())
		return -1;
	return 0;
}

int cpuinfo_check(void)
{
	if (cpu_init())
		return 1;
	if (cpu_validate_cpuinfo())
		return 1;
	return 0;
}
