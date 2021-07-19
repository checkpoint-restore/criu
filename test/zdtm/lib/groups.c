#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc = "Group starter";
const char *test_author = "Pavel Emelianov <xemul@parallels.com>";

int main(int argc, char **argv)
{
	int sret = 0;
	char *env;
	char sh[1024];

	test_init(argc, argv);

	env = getenv("ZDTM_TESTS");
	if (env[0] != '\0') {
		unsetenv("ZDTM_NEWNS");
		unsetenv("ZDTM_GROUPS");
		unsetenv("ZDTM_UID");
		unsetenv("ZDTM_GID");
		unsetenv("ZDTM_ROOT");

		test_msg("List: [%s]\n", env);
		sprintf(sh, "sh /%s.start", env);
		system(sh);
	}

	test_daemon();
	test_waitsig();

	if (env[0] != '\0') {
		sprintf(sh, "sh /%s.stop", env);
		sret = system(sh);
	}

	if (sret == 0)
		pass();
	else
		fail("Some subs failed");

	return 0;
}
