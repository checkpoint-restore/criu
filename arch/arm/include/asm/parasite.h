#ifndef __ASM_PARASITE_H__
#define __ASM_PARASITE_H__

static inline u32 arch_get_tls(void)
{
	return ((u32 (*)())0xffff0fe0)();
}

#endif
