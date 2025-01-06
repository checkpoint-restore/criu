#ifndef __ASM_PARASITE_H__
#define __ASM_PARASITE_H__

static inline void arch_get_tls(tls_t *ptls)
{
	asm("rdhwr %0, $29" : "=r"(*ptls));
}

#endif
