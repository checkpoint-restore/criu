#ifndef __CR_PROCESSOR_H__
#define __CR_PROCESSOR_H__

/* Copied from linux kernel arch/arm/include/asm/unified.h */

#define WASM(instr) #instr

/* Copied from linux kernel arch/arm/include/asm/processor.h */

#define __ALT_SMP_ASM(smp, up)                     \
	"9998:	" smp "\n"                         \
	"	.pushsection \".alt.smp.init\", \"a\"\n" \
	"	.long	9998b\n"                           \
	"	" up "\n"                          \
	"	.popsection\n"

static inline void prefetchw(const void *ptr)
{
	__asm__ __volatile__(
		".arch_extension	mp\n" __ALT_SMP_ASM(WASM(pldw) "\t%a0", WASM(pld) "\t%a0")::"p"(ptr));
}

#endif /* __CR_PROCESSOR_H__ */
