#ifndef __ASM_PARASITE_H__
#define __ASM_PARASITE_H__

#ifdef CONFIG_X86_32
# define __parasite_entry __attribute__((regparm(3)))
#endif

static inline void arch_get_tls(tls_t *ptls) { (void)ptls; }

#endif
