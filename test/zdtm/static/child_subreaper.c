#include <stdlib.h>
#include <sys/prctl.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that child subreaper attribute is restored";
const char *test_author	= "Michał Cłapiński <mclapinski@google.com>";

int main(int argc, char **argv)
{
	int cs_before = 1, cs_after, ret;

	test_init(argc, argv);

	ret = prctl(PR_SET_CHILD_SUBREAPER, cs_before, 0, 0, 0);
	if (ret) {
		pr_perror("Can't set child subreaper attribute, err = %d", ret);
		exit(1);
	}

	test_daemon();
	test_waitsig();

	ret = prctl(PR_GET_CHILD_SUBREAPER, (unsigned long)&cs_after, 0, 0, 0);
	if (ret) {
		pr_perror("Can't get child subreaper attribute, err = %d", ret);
		exit(1);
	}

	if (cs_before != cs_after)
		fail("%d != %d\n", cs_before, cs_after);
	else
		pass();

	return 0;
}
