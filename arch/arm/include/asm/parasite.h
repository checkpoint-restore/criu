#ifndef __ASM_PARASITE_H__
#define __ASM_PARASITE_H__

static inline u32 arch_get_tls(void) {
	uint32_t res;

	asm (
	     "adr %%r1, 1f              \n"
	     "ldr %%r1, [%%r1]          \n"
	     "push { %%r7, %%lr }       \n"
	     "blx %%r1                  \n"
	     "pop { %%r7, %%lr }        \n"
	     "mov %0, %%r0              \n"
	     "b   2f                    \n"

	     "1:                        \n"
	     ".word 0xffff0fe0          \n"

	     "2:                        \n"
	     :"=r"(res)
	     :
	     : "r0", "r1", "memory"
	     );

	return res;
}

#endif
