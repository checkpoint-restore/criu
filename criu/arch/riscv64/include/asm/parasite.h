#ifndef __ASM_PARASITE_H__
#define __ASM_PARASITE_H__

/*
 * This function is used to retrieve the value of the thread pointer (tp)
 * in RISC-V architecture, which is typically used for thread-local storage (TLS).
 * The value is then stored in the provided tls_t pointer.
 */
static inline void arch_get_tls(tls_t *ptls)
{
	tls_t tls;
	asm("mv %0, tp" : "=r"(tls));
	*ptls = tls;
}

#endif
