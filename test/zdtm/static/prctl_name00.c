/*
 * Check that the process name set via PR_SET_NAME is preserved
 * across checkpoint and restore.
 */
#include <string.h>
#include <sys/prctl.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that PR_SET_NAME survives C/R";
const char *test_author	= "Mayur Galhate <mayur_galhate@example.com>";

#define TEST_NAME "zdtm-prctl00"

int main(int argc, char **argv)
{
	char name[16];	/* kernel limit: 16 bytes including NUL */

	test_init(argc, argv);

	if (prctl(PR_SET_NAME, TEST_NAME, 0, 0, 0)) {
		pr_perror("Can't set process name");
		return 1;
	}

	test_daemon();
	test_waitsig();

	memset(name, 0, sizeof(name));
	if (prctl(PR_GET_NAME, name, 0, 0, 0)) {
		fail("Can't get process name after restore");
		return 1;
	}

	/*
	 * The kernel truncates the name to 15 characters (+NUL),
	 * so compare only up to that length.
	 */
	if (strncmp(name, TEST_NAME, sizeof(name) - 1))
		fail("Process name changed: expected \"%s\", got \"%s\"",
		     TEST_NAME, name);
	else
		pass();

	return 0;
}
