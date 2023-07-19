#include <stdlib.h>
#include <sys/prctl.h>

#include "zdtmtst.h"

const char *test_doc = "Check that NO_NEW_PRIVS attribute is restored";
const char *test_author = "Michał Mirosław <emmir@google.com>";

int main(int argc, char **argv)
{
	int ret;

	test_init(argc, argv);

	ret = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
	if (ret < 0) {
		pr_perror("Can't read NO_NEW_PRIVS attribute");
		return 1;
	}
	if (ret != 0)
		fail("initial NO_NEW_PRIVS = %d != 0", ret);

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (ret) {
		pr_perror("Can't set NO_NEW_PRIVS attribute");
		return 1;
	}

	test_daemon();
	test_waitsig();

	ret = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
	if (ret < 0) {
		pr_perror("Can't read NO_NEW_PRIVS attribute");
		return 1;
	}
	if (ret != 1)
		fail("restored NO_NEW_PRIVS = %d != 1", ret);

	pass();
	return 0;
}
