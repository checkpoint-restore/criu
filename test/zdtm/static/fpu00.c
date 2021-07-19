#include <stdlib.h>
#include <pthread.h>

#include "zdtmtst.h"

const char *test_doc = "Start a calculation, leaving FPU in a certain state,\n"
		       "before migration, continue after";
const char *test_author = "Pavel Emelianov <xemul@parallels.com>";

#if defined(__i386__) || defined(__x86_64__)

#include "cpuid.h"

void start(float a, float b, float c, float d)
{
	__asm__ volatile("flds  %0\n"
			 "fadds %1\n"
			 "flds  %2\n"
			 "fadds %3\n"
			 "fmulp %%st(1)\n"
			 :
			 : "m"(a), "m"(b), "m"(c), "m"(d));
}

float finish(void)
{
	float res;

	__asm__ volatile("fstps %0\n" : "=m"(res));
	return res;
}

#define CPUID_FEAT_EDX_FPU (1 << 0)

int chk_proc_fpu(void)
{
	uint32_t eax, ebx, ecx, edx;

	cpuid(1, &eax, &ebx, &ecx, &edx);

	return edx & CPUID_FEAT_EDX_FPU;
}

void *run_fpu_test(void *unused)
{
	float a, b, c, d;
	float res1, res2;

	a = drand48();
	b = drand48();
	c = drand48();
	d = drand48();

	start(a, b, c, d);
	res1 = finish();

	start(a, b, c, d);

	test_daemon();
	test_waitsig();

	res2 = finish();

	if (res1 != res2)
		fail("%f != %f", res1, res2);
	else
		pass();

	return (void *)(uintptr_t)(res1 != res2);
}

int main(int argc, char **argv)
{
	test_init(argc, argv);

	if (!chk_proc_fpu()) {
		skip("FPU not supported");
		return 1;
	}

#ifdef ZDTM_FPU00_RUN_IN_THREAD
	/* Check if thread's fpu state is preserved */
	{
		pthread_t child;
		void *ret;

		if (pthread_create(&child, NULL, &run_fpu_test, NULL)) {
			pr_perror("Can't create pthread");
			exit(1);
		}

		if (pthread_join(child, &ret)) {
			pr_perror("Can't join pthread");
			exit(1);
		}

		exit(!!ret);
	}
#else
	return !!run_fpu_test(NULL);
#endif
}

#else

int main(int argc, char *argv[])
{
	test_init(argc, argv);
	skip("Unsupported arch");
	return 0;
}

#endif
