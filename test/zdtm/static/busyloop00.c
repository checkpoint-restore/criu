#include "zdtmtst.h"

const char *test_doc = "Run busy loop while migrating";
const char *test_author = "Roman Kagan <rkagan@parallels.com>";

int main(int argc, char **argv)
{
	test_init(argc, argv);

	test_daemon();

	while (test_go())
		;

	pass();

	return 0;
}
