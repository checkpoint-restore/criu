#ifndef __ASM_PARASITE_H__
#define __ASM_PARASITE_H__

/* TLS is accessed through r13, which is already processed */
static inline void arch_get_tls(tls_t *ptls) { (void)ptls; }

#endif
