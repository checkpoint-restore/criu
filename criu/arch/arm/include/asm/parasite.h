#ifndef __ASM_PARASITE_H__
#define __ASM_PARASITE_H__

/* kuser_get_tls() kernel-provided user-helper, the address is emulated */
static inline void arch_get_tls(tls_t *ptls)
{
	*ptls = ((tls_t(*)(void))0xffff0fe0)();
}

#endif
