#define _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <grp.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that supplementary groups are supported";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

int main(int argc, char **argv)
{
	int ng;
	unsigned int *grp, *grp2, i, max;

	test_init(argc, argv);

	ng = getgroups(0, NULL);
	if (ng < 0) {
		pr_perror("Can't get groups");
		return -1;
	}

	grp = malloc((ng + 1) * sizeof(*grp));
	ng = getgroups(ng, grp);
	if (ng < 0) {
		pr_perror("Can't get groups2");
		return -1;
	}

	max = 0;
	for (i = 0; i < ng; i++)
		if (max < grp[i])
			max = grp[i];

	grp[ng++] = max + 1;

	if (setgroups(ng, grp) < 0) {
		pr_perror("Can't set groups");
		return -1;
	}

	test_daemon();
	test_waitsig();

	grp2 = malloc(ng * sizeof(*grp2));

	if (getgroups(ng, grp2) != ng) {
		fail("Nr groups changed");
		return -1;
	}

	if (memcmp(grp, grp2, ng * sizeof(*grp))) {
		fail("Groups have changed");
		return -1;
	}

	pass();

	return 0;
}
