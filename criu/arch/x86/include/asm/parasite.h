#ifndef __ASM_PARASITE_H__
#define __ASM_PARASITE_H__

/*
 * TLS is accessed through PTRACE_GET_THREAD_AREA,
 * see compel_arch_fetch_thread_area().
 */
static inline void arch_get_tls(tls_t *ptls)
{
	(void)ptls;
}

#endif
