#ifndef __ASM_PARASITE_H__
#define __ASM_PARASITE_H__

static inline void arch_get_tls(tls_t *ptls)
{
	tls_t tls;
	asm("mrs %0, tpidr_el0" : "=r"(tls));
	*ptls = tls;
}

#endif
