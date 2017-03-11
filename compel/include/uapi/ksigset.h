#ifndef __COMPEL_KSIGSET_H__
#define __COMPEL_KSIGSET_H__

#include <compel/plugins/std/asm/syscall-types.h>

static inline void ksigfillset(k_rtsigset_t *set)
{
	int i;
	for (i = 0; i < _KNSIG_WORDS; i++)
		set->sig[i] = (unsigned long)-1;
}

static inline void ksigemptyset(k_rtsigset_t *set)
{
	int i;
	for (i = 0; i < _KNSIG_WORDS; i++)
		set->sig[i] = 0;
}

static inline void ksigaddset(k_rtsigset_t *set, int _sig)
{
	int sig = _sig - 1;
	set->sig[sig / _NSIG_BPW] |= 1UL << (sig % _NSIG_BPW);
}
#endif
