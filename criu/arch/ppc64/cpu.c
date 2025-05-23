#undef LOG_PREFIX
#define LOG_PREFIX "cpu: "

#include <sys/auxv.h>
#include <errno.h>
#include <asm/cputable.h>

#include "asm/types.h"

#include "cr_options.h"
#include "image.h"
#include "util.h"
#include "log.h"
#include "cpu.h"

#include "protobuf.h"
#include "images/cpuinfo.pb-c.h"

static compel_cpuinfo_t rt_cpuinfo;

#ifdef __LITTLE_ENDIAN__
#define CURRENT_ENDIANNESS CPUINFO_PPC64_ENTRY__ENDIANNESS__LITTLEENDIAN
#else
#define CURRENT_ENDIANNESS CPUINFO_PPC64_ENTRY__ENDIANESS__BIGENDIAN
#endif

int cpu_init(void)
{
	return compel_cpuid(&rt_cpuinfo);
}

int cpu_dump_cpuinfo(void)
{
	CpuinfoEntry cpu_info = CPUINFO_ENTRY__INIT;
	CpuinfoPpc64Entry cpu_ppc64_info = CPUINFO_PPC64_ENTRY__INIT;
	CpuinfoPpc64Entry *cpu_ppc64_info_ptr = &cpu_ppc64_info;
	struct cr_img *img;
	int ret = -1;

	img = open_image(CR_FD_CPUINFO, O_DUMP);
	if (!img)
		return -1;

	cpu_info.ppc64_entry = &cpu_ppc64_info_ptr;
	cpu_info.n_ppc64_entry = 1;

	cpu_ppc64_info.endian = CURRENT_ENDIANNESS;
	cpu_ppc64_info.n_hwcap = 2;
	cpu_ppc64_info.hwcap = rt_cpuinfo.hwcap;

	ret = pb_write_one(img, &cpu_info, PB_CPUINFO);

	close_image(img);
	return ret;
}

int cpu_validate_cpuinfo(void)
{
	CpuinfoEntry *cpu_info;
	CpuinfoPpc64Entry *cpu_ppc64_entry;
	struct cr_img *img;
	int ret = -1;
	img = open_image(CR_FD_CPUINFO, O_RSTR);
	if (!img)
		return -1;

	if (empty_image(img)) {
		pr_err("No cpuinfo image\n");
		close_image(img);
		return -1;
	}

	if (pb_read_one(img, &cpu_info, PB_CPUINFO) < 0)
		goto error;

	if (cpu_info->n_ppc64_entry != 1) {
		pr_err("No PPC64 related entry in image\n");
		goto error;
	}
	cpu_ppc64_entry = cpu_info->ppc64_entry[0];

	if (cpu_ppc64_entry->endian != CURRENT_ENDIANNESS) {
		pr_err("Bad endianness\n");
		goto error;
	}

	if (cpu_ppc64_entry->n_hwcap != 2) {
		pr_err("Hardware capabilities information missing\n");
		goto error;
	}

#define CHECK_FEATURE(s, f)                                                          \
	do {                                                                         \
		if ((cpu_ppc64_entry->hwcap[s] & f) && !(rt_cpuinfo.hwcap[s] & f)) { \
			pr_err("CPU Feature %s required by image "                   \
			       "is not supported on host.\n",                        \
			       #f);                                                  \
			goto error;                                                  \
		}                                                                    \
	} while (0)

#define REQUIRE_FEATURE(s, f)                                             \
	do {                                                              \
		if (!(cpu_ppc64_entry->hwcap[s] & f)) {                   \
			pr_err("CPU Feature %s missing in image.\n", #f); \
			goto error;                                       \
		}                                                         \
	} while (0)

	REQUIRE_FEATURE(0, PPC_FEATURE_64);
	REQUIRE_FEATURE(0, PPC_FEATURE_HAS_FPU);
	REQUIRE_FEATURE(0, PPC_FEATURE_HAS_MMU);
	REQUIRE_FEATURE(0, PPC_FEATURE_HAS_VSX);
	REQUIRE_FEATURE(1, PPC_FEATURE2_ARCH_2_07);

	CHECK_FEATURE(0, PPC_FEATURE_TRUE_LE);
	CHECK_FEATURE(1, PPC_FEATURE2_HTM);
	CHECK_FEATURE(1, PPC_FEATURE2_DSCR);
	CHECK_FEATURE(1, PPC_FEATURE2_EBB);
	CHECK_FEATURE(1, PPC_FEATURE2_ISEL);
	CHECK_FEATURE(1, PPC_FEATURE2_TAR);
	CHECK_FEATURE(1, PPC_FEATURE2_VEC_CRYPTO);

	ret = 0;
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
		return -1;

	if (cpu_validate_cpuinfo())
		return 1;

	return 0;
}
