#include <string.h>
#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc	= "Start a calculation, leaving MMX in a certain state,\n"
"before migration, continue after";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

#if defined(__i386__) || defined(__x86_64__)
void start(uint8_t *bytes, uint16_t *words)
{
	__asm__ volatile (
			  "movq %0, %%mm0\n"
			  "movq %1, %%mm1\n"
			  "movq %2, %%mm2\n"
			  "movq %3, %%mm3\n"
			  "paddb  %%mm0, %%mm1\n"
			  "psubw %%mm2, %%mm3\n"
			  :
			  : "m" (bytes[0]), "m" (bytes[8]),
			    "m" (words[0]), "m" (words[4])
			 );
}

void finish(uint8_t *bytes, uint16_t *words)
{
	__asm__ volatile (
			  "movq %%mm1, %0\n"
			  "movq %%mm3, %1\n"
			  : "=m" (bytes[0]), "=m" (words[0])
			 );
}

static inline void cpuid(unsigned int op, unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx)
{
        __asm__("cpuid"
                : "=a" (*eax),
                  "=b" (*ebx),
                  "=c" (*ecx),
                  "=d" (*edx)
                : "0" (op), "c"(0));
}

int chk_proc_mmx(void)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(1, &eax, &ebx, &ecx, &edx);
	return edx & (1 << 23);
}
#endif

int main(int argc, char **argv)
{
#if defined(__i386__) || defined(__x86_64__)
	uint8_t	 bytes[16];
	uint16_t words[8];
	uint32_t rnd[8];
	int i;

	uint8_t	 resbytes1[8], resbytes2[8];
	uint16_t reswords1[4], reswords2[4];
#endif

	test_init(argc, argv);
#if defined(__i386__) || defined(__x86_64__)
	if (!chk_proc_mmx()) {
		skip("MMX not supported");
		return 1;
	}

	for (i = 0; i < (sizeof(bytes) + sizeof(words)) / 4; i++)
		rnd[i] = mrand48();

	memcpy((uint8_t *) bytes, (uint8_t *) rnd, sizeof(bytes));
	memcpy((uint8_t *) words, (uint8_t *) rnd + sizeof(bytes), sizeof(words));

	start(bytes, words);
	finish(resbytes1, reswords1);

	start(bytes, words);

	test_daemon();
	test_waitsig();

	finish(resbytes2, reswords2);

	if (memcmp((uint8_t *) resbytes1, (uint8_t *) resbytes2, sizeof(resbytes1)))
		fail("byte op mismatch\n");
	else if (memcmp((uint8_t *) reswords1, (uint8_t *) reswords2, sizeof(reswords2)))
		fail("word op mismatch\n");
	else
		pass();
#else
	skip("Unsupported arch");
#endif
	return 0;
}
