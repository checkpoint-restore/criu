#ifndef __CR_ASM_CPU_H__
#define __CR_ASM_CPU_H__

#include <stdint.h>

/*
 * Adopted from linux kernel and enhanced from Intel/AMD manuals.
 */

#define NCAPINTS			(12) /* N 32-bit words worth of info */
#define NCAPINTS_BITS			(NCAPINTS * 32)

#define X86_FEATURE_FPU			(0*32+ 0) /* Onboard FPU */
#define X86_FEATURE_VME			(0*32+ 1) /* Virtual 8086 Mode Enhancements */
#define X86_FEATURE_DE			(0*32+ 2) /* Debugging Extensions */
#define X86_FEATURE_PSE			(0*32+ 3) /* Page Size Extension */
#define X86_FEATURE_TSC			(0*32+ 4) /* Time Stamp Counter */
#define X86_FEATURE_MSR			(0*32+ 5) /* Model Specific Registers RDMSR and WRMSR Instructions */
#define X86_FEATURE_PAE			(0*32+ 6) /* Physical Address Extension */
#define X86_FEATURE_MCE			(0*32+ 7) /* Machine Check Exception */
#define X86_FEATURE_CX8			(0*32+ 8) /* CMPXCHG8 instruction */
#define X86_FEATURE_APIC		(0*32+ 9) /* APIC On-Chip */
#define X86_FEATURE_SEP			(0*32+11) /* SYSENTER and SYSEXIT Instructions */
#define X86_FEATURE_MTRR		(0*32+12) /* Memory Type Range Registers */
#define X86_FEATURE_PGE			(0*32+13) /* PTE Global Bit */
#define X86_FEATURE_MCA			(0*32+14) /* Machine Check Architecture */
#define X86_FEATURE_CMOV		(0*32+15) /* CMOV instructions (plus FCMOVcc, FCOMI with FPU) */
#define X86_FEATURE_PAT			(0*32+16) /* Page Attribute Table */
#define X86_FEATURE_PSE36		(0*32+17) /* 36-Bit Page Size Extension */
#define X86_FEATURE_PSN			(0*32+18) /* Processor Serial Number */
#define X86_FEATURE_DS			(0*32+21) /* Debug Store */
#define X86_FEATURE_CLFLUSH		(0*32+19) /* CLFLUSH instruction */
#define X86_FEATURE_ACPI		(0*32+22) /* Thermal Monitor and Software Controlled Clock Facilities */
#define X86_FEATURE_MMX			(0*32+23) /* Multimedia Extensions */
#define X86_FEATURE_FXSR		(0*32+24) /* FXSAVE/FXRSTOR, CR4.OSFXSR */
#define X86_FEATURE_XMM			(0*32+25) /* "sse" */
#define X86_FEATURE_XMM2		(0*32+26) /* "sse2" */
#define X86_FEATURE_SS			(0*32+27) /* Self Snoop */
#define X86_FEATURE_HTT			(0*32+28) /* Multi-Threading */
#define X86_FEATURE_TM			(0*32+29) /* Thermal Monitor */
#define X86_FEATURE_PBE			(0*32+31) /* Pending Break Enable */

#define X86_FEATURE_SYSCALL		(1*32+11) /* SYSCALL/SYSRET */
#define X86_FEATURE_MMXEXT		(1*32+22) /* AMD MMX extensions */
#define X86_FEATURE_RDTSCP		(1*32+27) /* RDTSCP */
#define X86_FEATURE_3DNOWEXT		(1*32+30) /* AMD 3DNow! extensions */
#define X86_FEATURE_3DNOW		(1*32+31) /* 3DNow! */

#define X86_FEATURE_REP_GOOD		(3*32+16) /* rep microcode works well */
#define X86_FEATURE_NOPL		(3*32+20) /* The NOPL (0F 1F) instructions */

#define X86_FEATURE_XMM3		(4*32+ 0) /* "pni" SSE-3 */
#define X86_FEATURE_PCLMULQDQ		(4*32+ 1) /* PCLMULQDQ instruction */
#define X86_FEATURE_DTES64		(4*32+ 2) /* 64-bit DS Area */
#define X86_FEATURE_MWAIT		(4*32+ 3) /* "monitor" Monitor/Mwait support */
#define X86_FEATURE_DSCPL		(4*32+ 4) /* CPL Qualified Debug Store */
#define X86_FEATURE_VMX			(4*32+ 5) /* Virtual Machine Extensions */
#define X86_FEATURE_SMX			(4*32+ 6) /* Safer Mode Extensions */
#define X86_FEATURE_EST			(4*32+ 7) /* Enhanced Intel SpeedStep technology */
#define X86_FEATURE_TM2			(4*32+ 8) /* Thermal Monitor 2 */
#define X86_FEATURE_SSSE3		(4*32+ 9) /* Supplemental SSE-3 */
#define X86_FEATURE_CNXTID		(4*32+10) /* L1 Context ID */
#define X86_FEATURE_FMA			(4*32+12) /* Fused multiply-add */
#define X86_FEATURE_CX16		(4*32+13) /* CMPXCHG16B */
#define X86_FEATURE_XTPR_UCTL		(4*32+14) /* xTPR Update Control */
#define X86_FEATURE_PDCM		(4*32+15) /* Perfmon and Debug Capability */
#define X86_FEATURE_PCID		(4*32+17) /* Process-context identifiers */
#define X86_FEATURE_DCA			(4*32+18) /* Ability to prefetch data from a memory mapped device */
#define X86_FEATURE_XMM4_1		(4*32+19) /* "sse4_1" SSE-4.1 */
#define X86_FEATURE_XMM4_2		(4*32+20) /* "sse4_2" SSE-4.2 */
#define X86_FEATURE_X2APIC		(4*32+21) /* x2APIC */
#define X86_FEATURE_MOVBE		(4*32+22) /* MOVBE instruction */
#define X86_FEATURE_POPCNT		(4*32+23) /* POPCNT instruction */
#define X86_FEATURE_TSCDL		(4*32+24) /* Local APIC timer supports one-shot operation using a TSC deadline value */
#define X86_FEATURE_AES			(4*32+25) /* AES instructions */
#define X86_FEATURE_XSAVE		(4*32+26) /* XSAVE/XRSTOR/XSETBV/XGETBV */
#define X86_FEATURE_OSXSAVE		(4*32+27) /* "" XSAVE enabled in the OS */
#define X86_FEATURE_AVX			(4*32+28) /* Advanced Vector Extensions */
#define X86_FEATURE_F16C		(4*32+29) /* 16-bit fp conversions */
#define X86_FEATURE_RDRAND		(4*32+30) /* The RDRAND instruction */

#define X86_FEATURE_ABM			(6*32+ 5) /* Advanced bit manipulation */
#define X86_FEATURE_SSE4A		(6*32+ 6) /* SSE-4A */
#define X86_FEATURE_MISALIGNSSE		(6*32+ 7) /* Misaligned SSE mode */
#define X86_FEATURE_3DNOWPREFETCH	(6*32+ 8) /* 3DNow prefetch instructions */
#define X86_FEATURE_XOP			(6*32+11) /* extended AVX instructions */
#define X86_FEATURE_FMA4		(6*32+16) /* 4 operands MAC instructions */
#define X86_FEATURE_TBM			(6*32+21) /* trailing bit manipulations */

#define X86_FEATURE_FSGSBASE		(9*32+ 0) /* Supports RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE */
#define X86_FEATURE_BMI1		(9*32+ 3) /* 1st group bit manipulation extensions */
#define X86_FEATURE_HLE			(9*32+ 4) /* Hardware Lock Elision */
#define X86_FEATURE_AVX2		(9*32+ 5) /* AVX2 instructions */
#define X86_FEATURE_SMEP		(9*32+ 7) /* Supervisor Mode Execution Protection */
#define X86_FEATURE_BMI2		(9*32+ 8) /* 2nd group bit manipulation extensions */
#define X86_FEATURE_ERMS		(9*32+ 9) /* Enhanced REP MOVSB/STOSB */
#define X86_FEATURE_INVPCID		(9*32+10) /* Invalidate Processor Context ID */
#define X86_FEATURE_RTM			(9*32+11) /* Restricted Transactional Memory */
#define X86_FEATURE_MPX			(9*32+14) /* Memory Protection Extension */
#define X86_FEATURE_AVX512F		(9*32+16) /* AVX-512 Foundation */
#define X86_FEATURE_AVX512DQ		(9*32+17) /* AVX-512 Foundation */
#define X86_FEATURE_RDSEED		(9*32+18) /* The RDSEED instruction */
#define X86_FEATURE_ADX			(9*32+19) /* The ADCX and ADOX instructions */
#define X86_FEATURE_SMAP		(9*32+20) /* Supervisor Mode Access Prevention */
#define X86_FEATURE_CLFLUSHOPT		(9*32+23) /* CLFLUSHOPT instruction */
#define X86_FEATURE_IPT			(9*32+25) /* Intel Processor Trace */
#define X86_FEATURE_AVX512PF		(9*32+26) /* AVX-512 Prefetch */
#define X86_FEATURE_AVX512ER		(9*32+27) /* AVX-512 Exponential and Reciprocal */
#define X86_FEATURE_AVX512CD		(9*32+28) /* AVX-512 Conflict Detection */
#define X86_FEATURE_SHA			(9*32+29) /* Intel SHA extensions */
#define X86_FEATURE_AVX512BW		(9*32+30) /* AVX-512 */
#define X86_FEATURE_AVXVL		(9*32+31) /* AVX-512 */

#define X86_FEATURE_XSAVEOPT		(10*32+0) /* XSAVEOPT */
#define X86_FEATURE_XSAVEC		(10*32+1) /* XSAVEC */
#define X86_FEATURE_XGETBV1		(10*32+2) /* XGETBV with ECX = 1 */
#define X86_FEATURE_XSAVES		(10*32+3) /* XSAVES/XRSTORS */

/*
 * Node 11 is our own, kernel has not such entry.
 */
#define X86_FEATURE_PREFETCHWT1		(11*32+0) /* The PREFETCHWT1 instruction */

enum {
	X86_VENDOR_INTEL	= 0,
	X86_VENDOR_AMD		= 1,

	X86_VENDOR_MAX
};

struct cpuinfo_x86 {
	uint8_t			x86_family;
	uint8_t			x86_vendor;
	uint8_t			x86_model;
	uint8_t			x86_mask;
	uint32_t		x86_capability[NCAPINTS];
	uint32_t		extended_cpuid_level;
	int			cpuid_level;
	char			x86_vendor_id[16];
	char			x86_model_id[64];
};

typedef struct cpuinfo_x86 compel_cpuinfo_t;

#endif /* __CR_ASM_CPU_H__ */
