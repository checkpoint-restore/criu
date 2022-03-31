#include <string.h>
#include <stdbool.h>

#include "compel-cpu.h"
#include "common/bitops.h"
#include "common/compiler.h"

#include "log.h"
#include "common/bug.h"

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

/*
 * Although we spell it out in here, the Processor Trace
 * xfeature is completely unused. We use other mechanisms
 * to save/restore PT state in Linux.
 */

static const char *const xfeature_names[] = {
	"x87 floating point registers",
	"SSE registers",
	"AVX registers",
	"MPX bounds registers",
	"MPX CSR",
	"AVX-512 opmask",
	"AVX-512 Hi256",
	"AVX-512 ZMM_Hi256",
	"Processor Trace",
	"Protection Keys User registers",
	"Hardware Duty Cycling",
};

static short xsave_cpuid_features[] = {
	X86_FEATURE_FPU,      X86_FEATURE_XMM,	   X86_FEATURE_AVX,	X86_FEATURE_MPX,
	X86_FEATURE_MPX,      X86_FEATURE_AVX512F, X86_FEATURE_AVX512F, X86_FEATURE_AVX512F,
	X86_FEATURE_INTEL_PT, X86_FEATURE_PKU,	   X86_FEATURE_HDC,
};

void compel_set_cpu_cap(compel_cpuinfo_t *c, unsigned int feature)
{
	if (likely(feature < NCAPINTS_BITS))
		set_bit(feature, (unsigned long *)c->x86_capability);
}

void compel_clear_cpu_cap(compel_cpuinfo_t *c, unsigned int feature)
{
	if (likely(feature < NCAPINTS_BITS))
		clear_bit(feature, (unsigned long *)c->x86_capability);
}

int compel_test_cpu_cap(compel_cpuinfo_t *c, unsigned int feature)
{
	if (likely(feature < NCAPINTS_BITS))
		return test_bit(feature, (unsigned long *)c->x86_capability);
	return 0;
}

int compel_test_fpu_cap(compel_cpuinfo_t *c, unsigned int feature)
{
	if (likely(feature < XFEATURE_MAX))
		return (c->xfeatures_mask & (1UL << feature));
	return 0;
}

static int compel_fpuid(compel_cpuinfo_t *c)
{
	unsigned int last_good_offset;
	uint32_t eax, ebx, ecx, edx;
	size_t i;

	BUILD_BUG_ON(ARRAY_SIZE(xsave_cpuid_features) != ARRAY_SIZE(xfeature_names));

	if (!compel_test_cpu_cap(c, X86_FEATURE_FPU)) {
		pr_err("fpu: No FPU detected\n");
		return -1;
	}

	if (!compel_test_cpu_cap(c, X86_FEATURE_XSAVE)) {
		pr_info("fpu: x87 FPU will use %s\n", compel_test_cpu_cap(c, X86_FEATURE_FXSR) ? "FXSAVE" : "FSAVE");
		return 0;
	}

	cpuid_count(XSTATE_CPUID, 0, &eax, &ebx, &ecx, &edx);
	c->xfeatures_mask = eax + ((uint64_t)edx << 32);

	if ((c->xfeatures_mask & XFEATURE_MASK_FPSSE) != XFEATURE_MASK_FPSSE) {
		/*
		 * This indicates that something really unexpected happened
		 * with the enumeration.
		 */
		pr_err("fpu: FP/SSE not present amongst the CPU's xstate features: 0x%llx\n",
		       (unsigned long long)c->xfeatures_mask);
		return -1;
	}

	/*
	 * Clear XSAVE features that are disabled in the normal CPUID.
	 */
	for (i = 0; i < ARRAY_SIZE(xsave_cpuid_features); i++) {
		if (!compel_test_cpu_cap(c, xsave_cpuid_features[i]))
			c->xfeatures_mask &= ~(1 << i);
	}

	c->xfeatures_mask &= XFEATURE_MASK_USER;
	c->xfeatures_mask &= ~XFEATURE_MASK_SUPERVISOR;

	/*
	 * xsaves is not enabled in userspace, so
	 * xsaves is mostly for debug purpose.
	 */
	cpuid_count(XSTATE_CPUID, 0, &eax, &ebx, &ecx, &edx);
	c->xsave_size = ebx;
	c->xsave_size_max = ecx;

	cpuid_count(XSTATE_CPUID, 1, &eax, &ebx, &ecx, &edx);
	c->xsaves_size = ebx;

	pr_debug("fpu: xfeatures_mask 0x%llx xsave_size %u xsave_size_max %u xsaves_size %u\n",
		 (unsigned long long)c->xfeatures_mask, c->xsave_size, c->xsave_size_max, c->xsaves_size);

	if (c->xsave_size_max > sizeof(struct xsave_struct))
		pr_warn_once("fpu: max xsave frame exceed xsave_struct (%u %u)\n", c->xsave_size_max,
			     (unsigned)sizeof(struct xsave_struct));

	memset(c->xstate_offsets, 0xff, sizeof(c->xstate_offsets));
	memset(c->xstate_sizes, 0xff, sizeof(c->xstate_sizes));
	memset(c->xstate_comp_offsets, 0xff, sizeof(c->xstate_comp_offsets));
	memset(c->xstate_comp_sizes, 0xff, sizeof(c->xstate_comp_sizes));

	/* start at the beginning of the "extended state" */
	last_good_offset = offsetof(struct xsave_struct, extended_state_area);

	/*
	 * The FP xstates and SSE xstates are legacy states. They are always
	 * in the fixed offsets in the xsave area in either compacted form
	 * or standard form.
	 */
	c->xstate_offsets[0] = 0;
	c->xstate_sizes[0] = offsetof(struct i387_fxsave_struct, xmm_space);
	c->xstate_offsets[1] = c->xstate_sizes[0];
	c->xstate_sizes[1] = FIELD_SIZEOF(struct i387_fxsave_struct, xmm_space);

	for (i = FIRST_EXTENDED_XFEATURE; i < XFEATURE_MAX; i++) {
		if (!(c->xfeatures_mask & (1UL << i)))
			continue;

		/*
		 * If an xfeature is supervisor state, the offset
		 * in EBX is invalid. We leave it to -1.
		 *
		 * SDM says: If state component 'i' is a user state component,
		 * ECX[0] return 0; if state component i is a supervisor
		 * state component, ECX[0] returns 1.
		 */
		cpuid_count(XSTATE_CPUID, i, &eax, &ebx, &ecx, &edx);
		if (!(ecx & 1))
			c->xstate_offsets[i] = ebx;

		c->xstate_sizes[i] = eax;

		/*
		 * In our xstate size checks, we assume that the
		 * highest-numbered xstate feature has the
		 * highest offset in the buffer.  Ensure it does.
		 */
		if (last_good_offset > c->xstate_offsets[i])
			pr_warn_once("fpu: misordered xstate %d %d\n", last_good_offset, c->xstate_offsets[i]);

		last_good_offset = c->xstate_offsets[i];
	}

	BUILD_BUG_ON(sizeof(c->xstate_offsets) != sizeof(c->xstate_sizes));
	BUILD_BUG_ON(sizeof(c->xstate_comp_offsets) != sizeof(c->xstate_comp_sizes));

	c->xstate_comp_offsets[0] = 0;
	c->xstate_comp_sizes[0] = offsetof(struct i387_fxsave_struct, xmm_space);
	c->xstate_comp_offsets[1] = c->xstate_comp_sizes[0];
	c->xstate_comp_sizes[1] = FIELD_SIZEOF(struct i387_fxsave_struct, xmm_space);

	if (!compel_test_cpu_cap(c, X86_FEATURE_XSAVES)) {
		for (i = FIRST_EXTENDED_XFEATURE; i < XFEATURE_MAX; i++) {
			if ((c->xfeatures_mask & (1UL << i))) {
				c->xstate_comp_offsets[i] = c->xstate_offsets[i];
				c->xstate_comp_sizes[i] = c->xstate_sizes[i];
			}
		}
	} else {
		c->xstate_comp_offsets[FIRST_EXTENDED_XFEATURE] = FXSAVE_SIZE + XSAVE_HDR_SIZE;

		for (i = FIRST_EXTENDED_XFEATURE; i < XFEATURE_MAX; i++) {
			if ((c->xfeatures_mask & (1UL << i)))
				c->xstate_comp_sizes[i] = c->xstate_sizes[i];
			else
				c->xstate_comp_sizes[i] = 0;

			if (i > FIRST_EXTENDED_XFEATURE) {
				c->xstate_comp_offsets[i] = c->xstate_comp_offsets[i - 1] + c->xstate_comp_sizes[i - 1];

				/*
				 * The value returned by ECX[1] indicates the alignment
				 * of state component 'i' when the compacted format
				 * of the extended region of an XSAVE area is used:
				 */
				cpuid_count(XSTATE_CPUID, i, &eax, &ebx, &ecx, &edx);
				if (ecx & 2)
					c->xstate_comp_offsets[i] = ALIGN(c->xstate_comp_offsets[i], 64);
			}
		}
	}

	if (!pr_quelled(COMPEL_LOG_DEBUG)) {
		for (i = 0; i < ARRAY_SIZE(c->xstate_offsets); i++) {
			if (!(c->xfeatures_mask & (1UL << i)))
				continue;
			pr_debug("fpu: %-32s xstate_offsets %6d / %-6d xstate_sizes %6d / %-6d\n", xfeature_names[i],
				 c->xstate_offsets[i], c->xstate_comp_offsets[i], c->xstate_sizes[i],
				 c->xstate_comp_sizes[i]);
		}
	}

	return 0;
}

int compel_cpuid(compel_cpuinfo_t *c)
{
	uint32_t eax, ebx, ecx, edx;

	/*
	 * See cpu_detect() in the kernel, also
	 * read cpuid specs not only from general
	 * SDM but for extended instructions set
	 * reference.
	 */

	/* Get vendor name */
	cpuid(0x00000000, (unsigned int *)&c->cpuid_level, (unsigned int *)&c->x86_vendor_id[0],
	      (unsigned int *)&c->x86_vendor_id[8], (unsigned int *)&c->x86_vendor_id[4]);

	if (!strcmp(c->x86_vendor_id, "GenuineIntel")) {
		c->x86_vendor = X86_VENDOR_INTEL;
	} else if (!strcmp(c->x86_vendor_id, "AuthenticAMD") || !strcmp(c->x86_vendor_id, "HygonGenuine")) {
		c->x86_vendor = X86_VENDOR_AMD;
	} else {
		pr_err("Unsupported CPU vendor %s\n", c->x86_vendor_id);
		return -1;
	}

	c->x86_family = 4;

	/* Intel-defined flags: level 0x00000001 */
	if (c->cpuid_level >= 0x00000001) {
		cpuid(0x00000001, &eax, &ebx, &ecx, &edx);
		c->x86_family = (eax >> 8) & 0xf;
		c->x86_model = (eax >> 4) & 0xf;
		c->x86_mask = eax & 0xf;

		if (c->x86_family == 0xf)
			c->x86_family += (eax >> 20) & 0xff;
		if (c->x86_family >= 0x6)
			c->x86_model += ((eax >> 16) & 0xf) << 4;

		c->x86_capability[CPUID_1_EDX] = edx;
		c->x86_capability[CPUID_1_ECX] = ecx;
	}

	/* Thermal and Power Management Leaf: level 0x00000006 (eax) */
	if (c->cpuid_level >= 0x00000006)
		c->x86_capability[CPUID_6_EAX] = cpuid_eax(0x00000006);

	/* Additional Intel-defined flags: level 0x00000007 */
	if (c->cpuid_level >= 0x00000007) {
		cpuid_count(0x00000007, 0, &eax, &ebx, &ecx, &edx);
		c->x86_capability[CPUID_7_0_EBX] = ebx;
		c->x86_capability[CPUID_7_0_ECX] = ecx;
		c->x86_capability[CPUID_7_0_EDX] = edx;
	}

	/* Extended state features: level 0x0000000d */
	if (c->cpuid_level >= 0x0000000d) {
		cpuid_count(0x0000000d, 1, &eax, &ebx, &ecx, &edx);
		c->x86_capability[CPUID_D_1_EAX] = eax;
	}

	/* Additional Intel-defined flags: level 0x0000000F */
	if (c->cpuid_level >= 0x0000000F) {
		/* QoS sub-leaf, EAX=0Fh, ECX=0 */
		cpuid_count(0x0000000F, 0, &eax, &ebx, &ecx, &edx);
		c->x86_capability[CPUID_F_0_EDX] = edx;

		if (compel_test_cpu_cap(c, X86_FEATURE_CQM_LLC)) {
			/* QoS sub-leaf, EAX=0Fh, ECX=1 */
			cpuid_count(0x0000000F, 1, &eax, &ebx, &ecx, &edx);
			c->x86_capability[CPUID_F_1_EDX] = edx;
		}
	}

	/* AMD-defined flags: level 0x80000001 */
	eax = cpuid_eax(0x80000000);
	c->extended_cpuid_level = eax;

	if ((eax & 0xffff0000) == 0x80000000) {
		if (eax >= 0x80000001) {
			cpuid(0x80000001, &eax, &ebx, &ecx, &edx);

			c->x86_capability[CPUID_8000_0001_ECX] = ecx;
			c->x86_capability[CPUID_8000_0001_EDX] = edx;
		}
	}

	/*
	 * We're don't care about scattered features for now,
	 * otherwise look into init_scattered_cpuid_features()
	 * in kernel.
	 *
	 * Same applies to speculation control. Look into
	 * init_speculation_control() otherwise.
	 */

	if (c->extended_cpuid_level >= 0x80000004) {
		unsigned int *v;
		char *p, *q;
		v = (unsigned int *)c->x86_model_id;
		cpuid(0x80000002, &v[0], &v[1], &v[2], &v[3]);
		cpuid(0x80000003, &v[4], &v[5], &v[6], &v[7]);
		cpuid(0x80000004, &v[8], &v[9], &v[10], &v[11]);
		c->x86_model_id[48] = 0;

		/*
		 * Intel chips right-justify this string for some dumb reason;
		 * undo that brain damage:
		 */
		p = q = &c->x86_model_id[0];
		while (*p == ' ')
			p++;
		if (p != q) {
			while (*p)
				*q++ = *p++;
			while (q <= &c->x86_model_id[48])
				*q++ = '\0'; /* Zero-pad the rest */
		}
	}

	if (c->extended_cpuid_level >= 0x80000007) {
		cpuid(0x80000007, &eax, &ebx, &ecx, &edx);

		c->x86_capability[CPUID_8000_0007_EBX] = ebx;
		c->x86_power = edx;
	}

	if (c->extended_cpuid_level >= 0x8000000a)
		c->x86_capability[CPUID_8000_000A_EDX] = cpuid_edx(0x8000000a);

	if (c->extended_cpuid_level >= 0x80000008)
		c->x86_capability[CPUID_8000_0008_EBX] = cpuid_ebx(0x80000008);

	/* On x86-64 CPUID is always present */
	compel_set_cpu_cap(c, X86_FEATURE_CPUID);

	/* On x86-64 NOP is always present */
	compel_set_cpu_cap(c, X86_FEATURE_NOPL);

	/*
	 * On x86-64 syscalls32 are enabled but we don't
	 * set it yet for backward compatibility reason
	 */
	//compel_set_cpu_cap(c, X86_FEATURE_SYSCALL32);

	/* See filter_cpuid_features in kernel */
	if ((int32_t)c->cpuid_level < (int32_t)0x0000000d)
		compel_clear_cpu_cap(c, X86_FEATURE_XSAVE);

	/*
	 * We only care about small subset from c_early_init:
	 * early_init_amd and early_init_intel
	 */
	switch (c->x86_vendor) {
	case X86_VENDOR_INTEL:
		/*
		 * Strictly speaking we need to read MSR_IA32_MISC_ENABLE
		 * here but on ring3 it's impossible.
		 */
		if (c->x86_family == 15) {
			compel_clear_cpu_cap(c, X86_FEATURE_REP_GOOD);
			compel_clear_cpu_cap(c, X86_FEATURE_ERMS);
		} else if (c->x86_family == 6) {
			/* On x86-64 rep is fine */
			compel_set_cpu_cap(c, X86_FEATURE_REP_GOOD);
		}

		break;
	case X86_VENDOR_AMD:
		/*
		 * Bit 31 in normal CPUID used for nonstandard 3DNow ID;
		 * 3DNow is IDd by bit 31 in extended CPUID (1*32+31) anyway
		 */
		compel_clear_cpu_cap(c, 0 * 32 + 31);
		if (c->x86_family >= 0x10)
			compel_set_cpu_cap(c, X86_FEATURE_REP_GOOD);
		if (c->x86_family == 0xf) {
			uint32_t level;

			/* On C+ stepping K8 rep microcode works well for copy/memset */
			level = cpuid_eax(1);
			if ((level >= 0x0f48 && level < 0x0f50) || level >= 0x0f58)
				compel_set_cpu_cap(c, X86_FEATURE_REP_GOOD);
		}
		break;
	}

	pr_debug("x86_family %u x86_vendor_id %s x86_model_id %s\n", c->x86_family, c->x86_vendor_id, c->x86_model_id);

	return compel_fpuid(c);
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
	if (feature >= FIRST_EXTENDED_XFEATURE && feature < XFEATURE_MAX)
		return rt_info.xstate_sizes[feature];
	return 0;
}

uint32_t compel_fpu_feature_offset(unsigned int feature)
{
	fetch_rt_cpuinfo();
	if (feature >= FIRST_EXTENDED_XFEATURE && feature < XFEATURE_MAX)
		return rt_info.xstate_offsets[feature];
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
