#ifndef __ASM_PARASITE_H__
#define __ASM_PARASITE_H__

static inline void arch_get_tls(tls_t *ptls)
{
	tls_t tls;
	asm volatile("or %0, $zero, $tp" : "=r"(tls));
	*ptls = tls;
}

#endif
