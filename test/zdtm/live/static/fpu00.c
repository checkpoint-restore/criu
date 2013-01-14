#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc	= "Start a calculation, leaving FPU in a certain state,\n"
"before migration, continue after";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

#if defined(__i386__) || defined(__x86_64__)
void start(float a, float b, float c, float d)
{
	__asm__ volatile (
			  "fld	%0\n"
			  "fadd	%1\n"
			  "fld	%2\n"
			  "fadd	%3\n"
			  "fmulp %%st(1)\n"
			  :
			  : "m" (a), "m" (b), "m" (c), "m" (d)
			 );
}

float finish(void)
{
	float res;

	__asm__ volatile (
			  "fstp	%0\n"
			  : "=m" (res)
			 );
	return res;
}

int chk_proc_fpu(void)
{
	unsigned long fi;

	__asm__ volatile (
			"mov $1, %%eax\n"
			"cpuid\n"
			: "=d" (fi) : : "eax"
		);
	return fi & (1 << 0);
}
#endif

int main(int argc, char ** argv)
{
#if defined(__i386__) || defined(__x86_64__)
	float a, b, c, d;
	float res1, res2;
#endif

	test_init(argc, argv);
#if defined(__i386__) || defined(__x86_64__)
	if (!chk_proc_fpu()) {
		skip("FPU not supported");
		return 1;
	}

	a = drand48();
	b = drand48();
	c = drand48();
	d = drand48();


	start(a, b, c, d);
	res1 = 	finish();

	start(a, b, c, d);

	test_daemon();
	test_waitsig();

	res2 = finish();

	if (res1 != res2)
		fail("%f != %f\n", res1, res2);
	else
		pass();
#else
	skip("Unsupported arch");
#endif
	return 0;
}
