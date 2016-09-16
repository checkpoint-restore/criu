#ifndef __CR_SIGNAL_H__
#define __CR_SIGNAL_H__
#include "asm/types.h"

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
	set->sig[sig / _NSIG_BPW] = 1 << (sig % _NSIG_BPW);
}
#endif
