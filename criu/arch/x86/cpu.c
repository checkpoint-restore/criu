#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>

#include "bitops.h"
#include "asm/types.h"
#include "asm/cpu.h"
#include <compel/asm/fpu.h>
#include <compel/cpu.h>

#include "common/compiler.h"

#include "cr_options.h"
#include "image.h"
#include "util.h"
#include "log.h"

#include "cpu.h"

#include "protobuf.h"
#include "images/cpuinfo.pb-c.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "cpu: "

static compel_cpuinfo_t rt_cpu_info;

int cpu_init(void)
{
	if (compel_cpuid(&rt_cpu_info))
		return -1;

	BUILD_BUG_ON(sizeof(struct xsave_struct) != XSAVE_SIZE);
	BUILD_BUG_ON(sizeof(struct i387_fxsave_struct) != FXSAVE_SIZE);

	/*
	 * Make sure that at least FPU is onboard
	 * and fxsave is supported.
	 */
	if (compel_cpu_has_feature(X86_FEATURE_FPU)) {
		if (!compel_cpu_has_feature(X86_FEATURE_FXSR)) {
			pr_err("missing support fxsave/restore insns\n");
			return -1;
		}
	}

	pr_debug("fpu:%d fxsr:%d xsave:%d\n",
		 !!compel_cpu_has_feature(X86_FEATURE_FPU),
		 !!compel_cpu_has_feature(X86_FEATURE_FXSR),
		 !!compel_cpu_has_feature(X86_FEATURE_OSXSAVE));

	return 0;
}

int cpu_dump_cpuinfo(void)
{
	CpuinfoEntry cpu_info = CPUINFO_ENTRY__INIT;
	CpuinfoX86Entry cpu_x86_info = CPUINFO_X86_ENTRY__INIT;
	CpuinfoX86Entry *cpu_x86_info_ptr = &cpu_x86_info;
	struct cr_img *img;

	img = open_image(CR_FD_CPUINFO, O_DUMP);
	if (!img)
		return -1;

	cpu_info.x86_entry = &cpu_x86_info_ptr;
	cpu_info.n_x86_entry = 1;

	cpu_x86_info.vendor_id = (rt_cpu_info.x86_vendor == X86_VENDOR_INTEL) ?
		CPUINFO_X86_ENTRY__VENDOR__INTEL :
		CPUINFO_X86_ENTRY__VENDOR__AMD;
	cpu_x86_info.cpu_family = rt_cpu_info.x86_family;
	cpu_x86_info.model = rt_cpu_info.x86_model;
	cpu_x86_info.stepping = rt_cpu_info.x86_mask;
	cpu_x86_info.capability_ver = 1;
	cpu_x86_info.n_capability = ARRAY_SIZE(rt_cpu_info.x86_capability);
	cpu_x86_info.capability = (void *)rt_cpu_info.x86_capability;

	if (rt_cpu_info.x86_model_id[0])
		cpu_x86_info.model_id = rt_cpu_info.x86_model_id;

	if (pb_write_one(img, &cpu_info, PB_CPUINFO) < 0) {
		close_image(img);
		return -1;
	}

	close_image(img);
	return 0;
}

#define __ins_bit(__l, __v)	(1u << ((__v) - 32u * (__l)))

static u32 x86_ins_capability_mask[NCAPINTS] = {
	[0] =
		__ins_bit(0, X86_FEATURE_FPU)		|
		__ins_bit(0, X86_FEATURE_TSC)		|
		__ins_bit(0, X86_FEATURE_CX8)		|
		__ins_bit(0, X86_FEATURE_SEP)		|
		__ins_bit(0, X86_FEATURE_CMOV)		|
		__ins_bit(0, X86_FEATURE_CLFLUSH)	|
		__ins_bit(0, X86_FEATURE_MMX)		|
		__ins_bit(0, X86_FEATURE_FXSR)		|
		__ins_bit(0, X86_FEATURE_XMM)		|
		__ins_bit(0, X86_FEATURE_XMM2),

	[1] =
		__ins_bit(1, X86_FEATURE_SYSCALL)	|
		__ins_bit(1, X86_FEATURE_MMXEXT)	|
		__ins_bit(1, X86_FEATURE_RDTSCP)	|
		__ins_bit(1, X86_FEATURE_3DNOWEXT)	|
		__ins_bit(1, X86_FEATURE_3DNOW),

	[3] =
		__ins_bit(3, X86_FEATURE_REP_GOOD)	|
		__ins_bit(3, X86_FEATURE_NOPL),

	[4] =
		__ins_bit(4, X86_FEATURE_XMM3)		|
		__ins_bit(4, X86_FEATURE_PCLMULQDQ)	|
		__ins_bit(4, X86_FEATURE_MWAIT)		|
		__ins_bit(4, X86_FEATURE_SSSE3)		|
		__ins_bit(4, X86_FEATURE_CX16)		|
		__ins_bit(4, X86_FEATURE_XMM4_1)	|
		__ins_bit(4, X86_FEATURE_XMM4_2)	|
		__ins_bit(4, X86_FEATURE_MOVBE)		|
		__ins_bit(4, X86_FEATURE_POPCNT)	|
		__ins_bit(4, X86_FEATURE_AES)		|
		__ins_bit(4, X86_FEATURE_XSAVE)		|
		__ins_bit(4, X86_FEATURE_OSXSAVE)	|
		__ins_bit(4, X86_FEATURE_AVX)		|
		__ins_bit(4, X86_FEATURE_F16C)		|
		__ins_bit(4, X86_FEATURE_RDRAND),

	[6] =
		__ins_bit(6, X86_FEATURE_ABM)		|
		__ins_bit(6, X86_FEATURE_SSE4A)		|
		__ins_bit(6, X86_FEATURE_MISALIGNSSE)	|
		__ins_bit(6, X86_FEATURE_3DNOWPREFETCH)	|
		__ins_bit(6, X86_FEATURE_XOP)		|
		__ins_bit(6, X86_FEATURE_FMA4)		|
		__ins_bit(6, X86_FEATURE_TBM),

	[9] =
		__ins_bit(9, X86_FEATURE_FSGSBASE)	|
		__ins_bit(9, X86_FEATURE_BMI1)		|
		__ins_bit(9, X86_FEATURE_HLE)		|
		__ins_bit(9, X86_FEATURE_AVX2)		|
		__ins_bit(9, X86_FEATURE_BMI2)		|
		__ins_bit(9, X86_FEATURE_ERMS)		|
		__ins_bit(9, X86_FEATURE_RTM)		|
		__ins_bit(9, X86_FEATURE_MPX)		|
		__ins_bit(9, X86_FEATURE_AVX512F)	|
		__ins_bit(9, X86_FEATURE_AVX512DQ)	|
		__ins_bit(9, X86_FEATURE_RDSEED)	|
		__ins_bit(9, X86_FEATURE_ADX)		|
		__ins_bit(9, X86_FEATURE_CLFLUSHOPT)	|
		__ins_bit(9, X86_FEATURE_AVX512PF)	|
		__ins_bit(9, X86_FEATURE_AVX512ER)	|
		__ins_bit(9, X86_FEATURE_AVX512CD)	|
		__ins_bit(9, X86_FEATURE_SHA)		|
		__ins_bit(9, X86_FEATURE_AVX512BW)	|
		__ins_bit(9, X86_FEATURE_AVXVL),

	[10] =
		__ins_bit(10, X86_FEATURE_XSAVEOPT)	|
		__ins_bit(10, X86_FEATURE_XSAVEC)	|
		__ins_bit(10, X86_FEATURE_XGETBV1)	|
		__ins_bit(10, X86_FEATURE_XSAVES),

	[11] =
		__ins_bit(11, X86_FEATURE_PREFETCHWT1),
};

#undef __ins_bit

static int cpu_validate_ins_features(CpuinfoX86Entry *img_x86_entry)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(rt_cpu_info.x86_capability); i++) {
		u32 s = img_x86_entry->capability[i] & x86_ins_capability_mask[i];
		u32 d = rt_cpu_info.x86_capability[i] & x86_ins_capability_mask[i];

		/*
		 * Destination might be more feature rich
		 * but not the reverse.
		 */
		if (s & ~d) {
			pr_err("CPU instruction capabilities do not match run time\n");
			return -1;
		}
	}

	return 0;
}

static int cpu_validate_features(CpuinfoX86Entry *img_x86_entry)
{
	if (img_x86_entry->n_capability != ARRAY_SIZE(rt_cpu_info.x86_capability)) {
		/*
		 * Image carries different number of bits.
		 * Simply reject, we can't guarantee anything
		 * in such case.
		 */
		pr_err("Size of features in image mismatch "
		       "one provided by run time CPU (%d:%d)\n",
		       (unsigned)img_x86_entry->n_capability,
		       (unsigned)ARRAY_SIZE(rt_cpu_info.x86_capability));
		return -1;
	}

	if (opts.cpu_cap == CPU_CAP_FPU) {
		/*
		 * If we're requested to check FPU only ignore
		 * any other bit. It's up to a user if the
		 * rest of mismatches won't cause problems.
		 */

#define __mismatch_fpu_bit(__bit)					\
		(test_bit(__bit, (void *)img_x86_entry->capability) &&	\
		 !compel_cpu_has_feature(__bit))
		if (__mismatch_fpu_bit(X86_FEATURE_FPU)		||
		    __mismatch_fpu_bit(X86_FEATURE_FXSR)	||
		    __mismatch_fpu_bit(X86_FEATURE_OSXSAVE)) {
			pr_err("FPU feature required by image "
			       "is not supported on host.\n");
			return -1;
		} else
			return 0;
#undef __mismatch_fpu_bit
	}

	/*
	 * Capability on instructions level only.
	 */
	if (opts.cpu_cap == CPU_CAP_INS)
		return cpu_validate_ins_features(img_x86_entry);

	/*
	 * Strict capability mode. Everything must match.
	 */
	if (memcmp(img_x86_entry->capability, rt_cpu_info.x86_capability,
		   sizeof(rt_cpu_info.x86_capability))) {
			pr_err("CPU capabilites do not match run time\n");
			return -1;
	}

	return 0;
}

int cpu_validate_cpuinfo(void)
{
	CpuinfoX86Entry *img_x86_entry;
	CpuinfoEntry *img_cpu_info;
	struct cr_img *img;
	int ret = -1;

	img = open_image(CR_FD_CPUINFO, O_RSTR);
	if (!img)
		return -1;

	if (pb_read_one(img, &img_cpu_info, PB_CPUINFO) < 0)
		goto err;

	if (img_cpu_info->n_x86_entry != 1) {
		pr_err("No x86 related cpuinfo in image, "
		       "corruption (n_x86_entry = %zi)\n",
		       img_cpu_info->n_x86_entry);
		goto err;
	}

	img_x86_entry = img_cpu_info->x86_entry[0];
	if (img_x86_entry->vendor_id != CPUINFO_X86_ENTRY__VENDOR__INTEL &&
	    img_x86_entry->vendor_id != CPUINFO_X86_ENTRY__VENDOR__AMD) {
		pr_err("Unknown cpu vendor %d\n", img_x86_entry->vendor_id);
		goto err;
	}

	if (img_x86_entry->n_capability != ARRAY_SIZE(rt_cpu_info.x86_capability)) {
		pr_err("Image carries %u words while %u expected\n",
		       (unsigned)img_x86_entry->n_capability,
		       (unsigned)ARRAY_SIZE(rt_cpu_info.x86_capability));
		goto err;
	}

	ret = cpu_validate_features(img_x86_entry);
err:
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

	/*
	 * Force to check all caps if empty passed,
	 * still allow to check instructions only
	 * and etc.
	 */
	if (!opts.cpu_cap)
		opts.cpu_cap = CPU_CAP_ALL;

	if (cpu_validate_cpuinfo())
		return 1;

	return 0;
}
