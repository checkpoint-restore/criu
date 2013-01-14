#include <string.h>
#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc	= "Start a calculation, leaving SSE2 in a certain state,\n"
			  "before migration, continue after";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

#if defined(__i386__) || defined(__x86_64__)
void start(double *in)
{
	__asm__ volatile (
			"movapd	%0, %%xmm0\n"
			"movapd	%1, %%xmm1\n"
			"addpd	%%xmm0, %%xmm1\n"
			"sqrtpd	%%xmm1, %%xmm2\n"
			:
			: "m" (in[0]), "m" (in[2])
		);
}

void finish(double *out)
{
	__asm__ volatile (
			"movapd	%%xmm1, %0\n"
			"movapd	%%xmm2, %1\n"
			: "=m" (out[0]), "=m" (out[2])
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

int chk_proc_sse2(void)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(1, &eax, &ebx, &ecx, &edx);
	return edx & (1 << 26);
}
#endif

int main(int argc, char **argv)
{
#if defined(__i386__) || defined(__x86_64__)
	double input[4] __attribute__((aligned(16)));
	double res1[4], res2[4];
	int i;
#endif

	test_init(argc, argv);
#if defined(__i386__) || defined(__x86_64__)
	if (!chk_proc_sse2()) {
		skip("SSE2 not supported");
		return 1;
	}

	for (i = 0; i < sizeof(input) / sizeof(double); i++)
		input[i] = drand48();

	start(input);
	finish(res1);

	start(input);

	test_daemon();
	test_waitsig();

	finish(res2);

	if (memcmp((uint8_t *) res1, (uint8_t *) res2, sizeof(res1)))
		fail("results differ\n");
	else
		pass();
#else
	skip("Unsupported arch");
#endif
	return 0;
}
