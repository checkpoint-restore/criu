#include <sys/stat.h>

#include "zdtmtst.h"

const char *test_doc = "Check that umask didn't change";
const char *test_author = "Pavel Emelianov <xemul@parallels.com>";

unsigned int mask;
TEST_OPTION(mask, uint, "umask", 1);

int main(int argc, char **argv)
{
	unsigned int cur_mask, mask2;

	test_init(argc, argv);

	cur_mask = umask(mask);

	test_daemon();
	test_waitsig();

	mask2 = umask(0);
	if (mask != mask2)
		fail("mask changed: %o != %o", mask, mask2);
	else
		pass();

	umask(cur_mask);
	return 0;
}
