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

static int cpu_has_unsupported_features(void)
{
	/*
	 * Put any unsupported features here.
	 */
	return 0;
}

int cpu_init(void)
{
	compel_cpu_copy_cpuinfo(&rt_cpu_info);

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

	pr_debug("fpu:%d fxsr:%d xsave:%d xsaveopt:%d xsavec:%d xgetbv1:%d xsaves:%d\n",
		 !!compel_cpu_has_feature(X86_FEATURE_FPU),
		 !!compel_cpu_has_feature(X86_FEATURE_FXSR),
		 !!compel_cpu_has_feature(X86_FEATURE_OSXSAVE),
		 !!compel_cpu_has_feature(X86_FEATURE_XSAVEOPT),
		 !!compel_cpu_has_feature(X86_FEATURE_XSAVEC),
		 !!compel_cpu_has_feature(X86_FEATURE_XGETBV1),
		 !!compel_cpu_has_feature(X86_FEATURE_XSAVES));

	return cpu_has_unsupported_features() ? -1 : 0;
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
	cpu_x86_info.capability_ver = 2;
	cpu_x86_info.n_capability = ARRAY_SIZE(rt_cpu_info.x86_capability);
	cpu_x86_info.capability = (void *)rt_cpu_info.x86_capability;
	cpu_x86_info.has_xfeatures_mask = true;
	cpu_x86_info.xfeatures_mask = rt_cpu_info.xfeatures_mask;

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
	[CPUID_1_EDX] =
		__ins_bit(CPUID_1_EDX, X86_FEATURE_FPU)				|
		__ins_bit(CPUID_1_EDX, X86_FEATURE_TSC)				|
		__ins_bit(CPUID_1_EDX, X86_FEATURE_CX8)				|
		__ins_bit(CPUID_1_EDX, X86_FEATURE_SEP)				|
		__ins_bit(CPUID_1_EDX, X86_FEATURE_CMOV)			|
		__ins_bit(CPUID_1_EDX, X86_FEATURE_CLFLUSH)			|
		__ins_bit(CPUID_1_EDX, X86_FEATURE_MMX)				|
		__ins_bit(CPUID_1_EDX, X86_FEATURE_FXSR)			|
		__ins_bit(CPUID_1_EDX, X86_FEATURE_XMM)				|
		__ins_bit(CPUID_1_EDX, X86_FEATURE_XMM2),

	[CPUID_8000_0001_EDX] =
		__ins_bit(CPUID_8000_0001_EDX, X86_FEATURE_SYSCALL)		|
		__ins_bit(CPUID_8000_0001_EDX, X86_FEATURE_MMXEXT)		|
		__ins_bit(CPUID_8000_0001_EDX, X86_FEATURE_RDTSCP)		|
		__ins_bit(CPUID_8000_0001_EDX, X86_FEATURE_3DNOWEXT)		|
		__ins_bit(CPUID_8000_0001_EDX, X86_FEATURE_3DNOW),

	[CPUID_LNX_1] =
		__ins_bit(CPUID_LNX_1, X86_FEATURE_REP_GOOD)			|
		__ins_bit(CPUID_LNX_1, X86_FEATURE_NOPL),

	[CPUID_1_ECX] =
		__ins_bit(CPUID_1_ECX, X86_FEATURE_XMM3)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_PCLMULQDQ)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_MWAIT)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_SSSE3)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_CX16)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_XMM4_1)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_XMM4_2)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_MOVBE)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_POPCNT)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_AES)				|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_XSAVE)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_OSXSAVE)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_AVX)				|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_F16C)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_RDRAND),

	[CPUID_8000_0001_ECX] =
		__ins_bit(CPUID_8000_0001_ECX, X86_FEATURE_ABM)			|
		__ins_bit(CPUID_8000_0001_ECX, X86_FEATURE_SSE4A)		|
		__ins_bit(CPUID_8000_0001_ECX, X86_FEATURE_MISALIGNSSE)		|
		__ins_bit(CPUID_8000_0001_ECX, X86_FEATURE_3DNOWPREFETCH)	|
		__ins_bit(CPUID_8000_0001_ECX, X86_FEATURE_XOP)			|
		__ins_bit(CPUID_8000_0001_ECX, X86_FEATURE_FMA4)		|
		__ins_bit(CPUID_8000_0001_ECX, X86_FEATURE_TBM),

	[CPUID_7_0_EBX] =
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_FSGSBASE)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_BMI1)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_HLE)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_AVX2)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_BMI2)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_ERMS)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_RTM)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_MPX)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_AVX512F)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_AVX512DQ)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_RDSEED)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_ADX)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_CLFLUSHOPT)		|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_AVX512PF)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_AVX512ER)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_AVX512CD)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_SHA_NI)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_AVX512BW)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_AVX512VL),

	[CPUID_D_1_EAX] =
		__ins_bit(CPUID_D_1_EAX, X86_FEATURE_XSAVEOPT)			|
		__ins_bit(CPUID_D_1_EAX, X86_FEATURE_XSAVEC)			|
		__ins_bit(CPUID_D_1_EAX, X86_FEATURE_XGETBV1),

	[CPUID_7_0_ECX] =
		__ins_bit(CPUID_7_0_ECX, X86_FEATURE_AVX512VBMI)		|
		__ins_bit(CPUID_7_0_ECX, X86_FEATURE_AVX512_VBMI2)		|
		__ins_bit(CPUID_7_0_ECX, X86_FEATURE_GFNI)			|
		__ins_bit(CPUID_7_0_ECX, X86_FEATURE_VAES)			|
		__ins_bit(CPUID_7_0_ECX, X86_FEATURE_VPCLMULQDQ)		|
		__ins_bit(CPUID_7_0_ECX, X86_FEATURE_AVX512_VNNI)		|
		__ins_bit(CPUID_7_0_ECX, X86_FEATURE_AVX512_BITALG)		|
		__ins_bit(CPUID_7_0_ECX, X86_FEATURE_TME)			|
		__ins_bit(CPUID_7_0_ECX, X86_FEATURE_AVX512_VPOPCNTDQ)		|
		__ins_bit(CPUID_7_0_ECX, X86_FEATURE_RDPID),

	[CPUID_8000_0008_EBX] =
		__ins_bit(CPUID_8000_0008_EBX, X86_FEATURE_CLZERO),

	[CPUID_7_0_EDX] =
		__ins_bit(CPUID_7_0_EDX, X86_FEATURE_AVX512_4VNNIW)		|
		__ins_bit(CPUID_7_0_EDX, X86_FEATURE_AVX512_4FMAPS),
};

#undef __ins_bit

static int cpu_validate_ins_features(compel_cpuinfo_t *cpu_info)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(cpu_info->x86_capability); i++) {
		u32 s = cpu_info->x86_capability[i] & x86_ins_capability_mask[i];
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

static int cpu_validate_features(compel_cpuinfo_t *cpu_info)
{
	if (cpu_has_unsupported_features())
		return -1;

	if (opts.cpu_cap == CPU_CAP_FPU) {
		/*
		 * If we're requested to check FPU only ignore
		 * any other bit. It's up to a user if the
		 * rest of mismatches won't cause problems.
		 */

#define __mismatch_fpu_bit(__bit)					\
		(test_bit(__bit, (void *)cpu_info->x86_capability) &&	\
		 !compel_cpu_has_feature(__bit))
		if (__mismatch_fpu_bit(X86_FEATURE_FPU)		||
		    __mismatch_fpu_bit(X86_FEATURE_FXSR)	||
		    __mismatch_fpu_bit(X86_FEATURE_OSXSAVE)	||
		    __mismatch_fpu_bit(X86_FEATURE_XSAVES)) {
			pr_err("FPU feature required by image "
			       "is not supported on host "
			       "(fpu:%d fxsr:%d osxsave:%d xsaves:%d)\n",
			       __mismatch_fpu_bit(X86_FEATURE_FPU),
			       __mismatch_fpu_bit(X86_FEATURE_FXSR),
			       __mismatch_fpu_bit(X86_FEATURE_OSXSAVE),
			       __mismatch_fpu_bit(X86_FEATURE_XSAVES));
			return -1;
		} else
			return 0;
#undef __mismatch_fpu_bit
	}

	/*
	 * Make sure the xsave features are at least not less
	 * than current cpu supports.
	 */
	if (cpu_info->xfeatures_mask > rt_cpu_info.xfeatures_mask) {
		uint64_t m = cpu_info->xfeatures_mask & ~rt_cpu_info.xfeatures_mask;
		pr_err("CPU xfeatures has unsupported bits (%#llx)\n",
		       (unsigned long long)m);
		return -1;
	}

	/*
	 * Capability on instructions level only.
	 */
	if (opts.cpu_cap == CPU_CAP_INS)
		return cpu_validate_ins_features(cpu_info);

	/*
	 * Strict capability mode. Everything must match.
	 */
	if (memcmp(cpu_info->x86_capability, rt_cpu_info.x86_capability,
		   sizeof(cpu_info->x86_capability))) {
		pr_err("CPU capabilites do not match run time\n");
		return -1;
	}

	return 0;
}

static const struct {
	const uint32_t	capability_ver;
	const uint32_t	ncapints;
} ncapints[] = {
	{ .capability_ver = 1, .ncapints = NCAPINTS_V1 },
	{ .capability_ver = 2, .ncapints = NCAPINTS_V2 },
};

static compel_cpuinfo_t *img_to_cpuinfo(CpuinfoX86Entry *img_x86_entry)
{
	compel_cpuinfo_t *cpu_info;
	size_t size, i;

	BUILD_BUG_ON(sizeof(img_x86_entry->capability[0]) !=
		     sizeof(cpu_info->x86_capability[0]));
	BUILD_BUG_ON(ARRAY_SIZE(rt_cpu_info.x86_capability) != NCAPINTS);

	if (img_x86_entry->vendor_id != CPUINFO_X86_ENTRY__VENDOR__INTEL &&
	    img_x86_entry->vendor_id != CPUINFO_X86_ENTRY__VENDOR__AMD) {
			pr_err("Image carries unknown vendor %u\n",
			       (unsigned)img_x86_entry->vendor_id);
			return NULL;
	}

	for (i = 0; i < ARRAY_SIZE(ncapints); i++) {
		if (img_x86_entry->capability_ver == ncapints[i].capability_ver) {
			if (img_x86_entry->n_capability != ncapints[i].ncapints) {
				pr_err("Image carries %u words while %u expected\n",
				       (unsigned)img_x86_entry->n_capability,
				       (unsigned)ncapints[i].ncapints);
				return NULL;
			}
			break;
		}
	}

	if (i >= ARRAY_SIZE(ncapints)) {
		pr_err("Image carries unknown capability version %d\n",
		       (unsigned)img_x86_entry->capability_ver);
		return NULL;
	}

	cpu_info = xzalloc(sizeof(*cpu_info));
	if (!cpu_info)
		return NULL;

	/*
	 * Copy caps from image and fill the left ones from
	 * run-time infomation for easier compatibility testing.
	 */
	size = sizeof(img_x86_entry->capability[0]) * img_x86_entry->n_capability;
	memcpy(cpu_info->x86_capability, img_x86_entry->capability, size);
	if (img_x86_entry->capability_ver == 1) {
		memcpy(&cpu_info->x86_capability[NCAPINTS_V1],
		       &rt_cpu_info.x86_capability[NCAPINTS_V1],
		       (NCAPINTS_V2 - NCAPINTS_V1) * sizeof(rt_cpu_info.x86_capability[0]));
	}

	if (img_x86_entry->vendor_id == CPUINFO_X86_ENTRY__VENDOR__INTEL)
		cpu_info->x86_vendor	= X86_VENDOR_INTEL;
	else
		cpu_info->x86_vendor	= X86_VENDOR_AMD;
	cpu_info->x86_family		= img_x86_entry->cpu_family;
	cpu_info->x86_model		= img_x86_entry->model;
	cpu_info->x86_mask		= img_x86_entry->stepping;
	cpu_info->extended_cpuid_level	= rt_cpu_info.extended_cpuid_level;
	cpu_info->cpuid_level		= rt_cpu_info.cpuid_level;
	cpu_info->x86_power		= rt_cpu_info.x86_power;

	memcpy(cpu_info->x86_vendor_id, rt_cpu_info.x86_model_id, sizeof(cpu_info->x86_vendor_id));
	strncpy(cpu_info->x86_model_id, img_x86_entry->model_id, sizeof(cpu_info->x86_model_id) - 1);

	/*
	 * For old images where no xfeatures_mask present we
	 * simply fetch runtime cpu mask because later we will
	 * do either instruction capability check, either strict
	 * check for capabilities.
	 */
	if (!img_x86_entry->has_xfeatures_mask) {
		cpu_info->xfeatures_mask = rt_cpu_info.xfeatures_mask;
	} else
		cpu_info->xfeatures_mask = img_x86_entry->xfeatures_mask;

	return cpu_info;
}

int cpu_validate_cpuinfo(void)
{
	compel_cpuinfo_t *cpu_info = NULL;
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

	cpu_info = img_to_cpuinfo(img_x86_entry);
	if (cpu_info)
		ret = cpu_validate_features(cpu_info);
err:
	xfree(cpu_info);
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
