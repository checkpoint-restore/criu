#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc	= "Suspend while migrating";
const char *test_author	= "Roman Kagan <rkagan@parallels.com>";

int main(int argc, char ** argv)
{
	test_init(argc, argv);

	test_daemon();
	test_waitsig();

	pass();

	return 0;
}
