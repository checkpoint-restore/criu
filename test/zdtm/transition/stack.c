#include "zdtmtst.h"

const char *test_doc = "Tests that parasite code does not write past the start of the stack";
const char *test_author = "Younes Manton <ymanton@ca.ibm.com>";

int main(int argc, char **argv)
{
	test_init(argc, argv);

	test_daemon();
	test_waitsig();

	pass();

	return 0;
}
