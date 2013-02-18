#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>

#include "asm/bitops.h"
#include "asm/types.h"
#include "asm/cpu.h"
#include "asm/fpu.h"

#include "compiler.h"

#include "proc_parse.h"
#include "util.h"
#include "log.h"

#include "cpu.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "cpu: "

const char * const x86_cap_flags[NCAPINTS_BITS] = {
	[X86_FEATURE_FPU]                = "fpu",
	[X86_FEATURE_FXSR]               = "fxsr",
	[X86_FEATURE_XSAVE]              = "xsave",
};

static DECLARE_BITMAP(cpu_features, NCAPINTS_BITS);
#define cpu_has(bit)	test_bit(bit, cpu_features)

void cpu_set_feature(unsigned int feature)
{
	if (likely(feature < NCAPINTS_BITS))
		set_bit(feature, cpu_features);
}

bool cpu_has_feature(unsigned int feature)
{
	if (likely(feature < NCAPINTS_BITS))
		return cpu_has(feature);
	return false;
}

static int proc_cpuinfo_match(char *tok)
{
	if (!strcmp(tok, x86_cap_flags[X86_FEATURE_FXSR]))
		cpu_set_feature(X86_FEATURE_FXSR);
	else if (!strcmp(tok, x86_cap_flags[X86_FEATURE_XSAVE]))
		cpu_set_feature(X86_FEATURE_XSAVE);
	else if (!strcmp(tok, x86_cap_flags[X86_FEATURE_FPU]))
		cpu_set_feature(X86_FEATURE_FPU);
	return 0;
}

int cpu_init(void)
{
	if (parse_cpuinfo_features(proc_cpuinfo_match))
		return -1;

	BUILD_BUG_ON(sizeof(struct xsave_struct) != XSAVE_SIZE);
	BUILD_BUG_ON(sizeof(struct i387_fxsave_struct) != FXSAVE_SIZE);

	/*
	 * Make sure that at least FPU is onboard
	 * and fxsave is supported.
	 */
	if (cpu_has(X86_FEATURE_FPU)) {
		if (!cpu_has(X86_FEATURE_FXSR)) {
			pr_err("missing support fxsave/restore insns\n");
			return -1;
		}
	}

	pr_debug("fpu:%d fxsr:%d xsave:%d\n",
		 !!cpu_has(X86_FEATURE_FPU),
		 !!cpu_has(X86_FEATURE_FXSR),
		 !!cpu_has(X86_FEATURE_XSAVE));

	return 0;
}
