#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that environment didn't change";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

char *envname;
TEST_OPTION(envname, string, "environment variable name", 1);

int main(int argc, char **argv)
{
	char *env;

	test_init(argc, argv);

	if (setenv(envname, test_author, 1)) {
		pr_perror("Can't set env var \"%s\" to \"%s\"", envname, test_author);
		exit(1);
	}

	test_daemon();
	test_waitsig();

	env = getenv(envname);
	if (!env) {
		fail("can't get env var \"%s\": %m\n", envname);
		goto out;
	}

	if (strcmp(env, test_author))
		fail("%s != %s\n", env, test_author);
	else
		pass();
out:
	return 0;
}
