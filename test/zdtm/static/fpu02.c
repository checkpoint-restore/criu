#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>

#include "zdtmtst.h"

#if defined(__i386__) || defined(__x86_64__)

#include "cpuid.h"

const char *test_doc	= "Test preserve of mxcsr in FPU";
const char *test_author	= "Dmitry Safonov <0x7f454c46@gmail.com>";

static int verify_cpu(void)
{
	unsigned int eax, ebx, ecx, edx;

	/* Do we have xsave? */
	cpuid(1, &eax, &ebx, &ecx, &edx);
	if (!(ecx & (1u << 27)))
		return -1;

	/* Is YMM here? */
	cpuid_count(0xd, 0, &eax, &ebx, &ecx, &edx);
	if ((eax & (0x4)) != 0x4)
		return -1;

	return 0;
}

#define __aligned __attribute__((aligned(64)))

static int fpu_test(void)
{
	uint32_t before, after;

	asm volatile("stmxcsr %0\n"
		     : "+m"(before));

	test_daemon();
	test_waitsig();

	asm volatile("stmxcsr %0\n"
		     : "+m"(after));

	test_msg("before: %x, after: %x\n", before, after);

	return (before != after);
}

static int bare_run(void)
{
	test_msg("Your cpu doesn't support ymm registers, skipping\n");

	test_daemon();
	test_waitsig();

	return 0;
}

int main(int argc, char *argv[])
{
	int ret = 0;

	test_init(argc, argv);

	ret = verify_cpu() ? bare_run() : fpu_test();

	if (!ret)
		pass();
	else
		fail();

	return 0;
}

#else

int main(int argc, char *argv[])
{
	test_init(argc, argv);
	skip("Unsupported arch");
	return 0;
}

#endif
