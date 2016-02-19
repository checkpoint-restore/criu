#include <stdlib.h>
#include <time.h>

#include "zdtmtst.h"

const char *test_doc	= "Initialize VFP registers before a migration,\n"
						  "check the VFP state is the same after a restore.";
const char *test_author	= "Alexander Karatshov <alekskartashov@parallels.com>";


#ifdef __arm__

int main(int argc, char ** argv)
{
	srand(time(0));

	int a = rand() % 100;
	int b = rand() % 100;
	int c = rand() % 100;
	int y1 = a + b*c;
	int y2;

	test_init(argc, argv);

	asm (
		".fpu neon				\n"
		"vmov.32	d0[0], %0	\n"
		"vmov.32	d1[0], %1	\n"
		"vmov.32	d2[0], %2	\n"
		".fpu softvfp			\n"
		: : "r"(a), "r"(b), "r"(c)
	);

	test_msg("Preparing to wait...\n");

	test_daemon();
	test_waitsig();

	test_msg("Restored.\n");

	asm (
		".fpu neon				\n"
		"vmul.I32	d3, d1, d2	\n"
		"vadd.I32	d4, d0, d3	\n"
		"vmov.32	%0, d4[0]	\n"
		".fpu softvfp			\n"
		: "=r"(y2)
	);

	if (y1 != y2)
		fail("VFP restoration failed: result = %d, expected = %d (a = %d, b = %d, c = %d)\n", y2, y1, a, b, c);
	else
		pass();

	return 0;
}

#else

int main(int argc, char *argv[])
{
	test_init(argc, argv);
	skip("This test is supposed to run on an ARM machine!");
	return 0;
}

#endif
