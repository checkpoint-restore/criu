#include <string.h>
#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc = "Start a calculation, leaving SSE in a certain state,\n"
		       "before migration, continue after";
const char *test_author = "Pavel Emelianov <xemul@parallels.com>";

#if defined(__i386__) || defined(__x86_64__)
void start(float *in)
{
	__asm__ volatile("movaps	%0, %%xmm0\n"
			 "movaps	%1, %%xmm1\n"
			 "addps	%%xmm0, %%xmm1\n"
			 "sqrtps	%%xmm1, %%xmm2\n"
			 :
			 : "m"(in[0]), "m"(in[4]));
}

void finish(float *out)
{
	__asm__ volatile("movaps	%%xmm1, %0\n"
			 "movaps	%%xmm2, %1\n"
			 : "=m"(out[0]), "=m"(out[4]));
}

static inline void cpuid(unsigned int op, unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx)
{
	__asm__("cpuid" : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx) : "0"(op), "c"(0));
}

int chk_proc_sse(void)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(1, &eax, &ebx, &ecx, &edx);
	return edx & (1 << 25);
}
#endif

int main(int argc, char **argv)
{
#if defined(__i386__) || defined(__x86_64__)
	float input[8] __attribute__((aligned(16)));
	float res1[8] __attribute__((aligned(16)));
	float res2[8] __attribute__((aligned(16)));
	int i;
#endif

	test_init(argc, argv);
#if defined(__i386__) || defined(__x86_64__)
	if (!chk_proc_sse()) {
		skip("SSE not supported");
		return 1;
	}
	for (i = 0; i < sizeof(input) / sizeof(float); i++)
		input[i] = drand48();

	start(input);
	finish(res1);

	start(input);
	finish(res1);

	test_daemon();
	test_waitsig();

	finish(res2);

	if (memcmp((uint8_t *)res1, (uint8_t *)res2, sizeof(res1)))
		fail("results differ");
	else
		pass();
#else
	skip("Unsupported arch");
#endif
	return 0;
}
