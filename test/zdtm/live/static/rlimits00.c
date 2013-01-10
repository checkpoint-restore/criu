#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that rlimits are saved";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

int main(int argc, char **argv)
{
	int r, changed = 0;
	struct rlimit rlims[RLIM_NLIMITS], trlim;

	test_init(argc, argv);

	for (r = 0; r < RLIM_NLIMITS; r++) {
		if (getrlimit(r, &rlims[r])) {
			err("Can't get rlimit");
			goto out;
		}

		if (rlims[r].rlim_cur > 1 &&
				rlims[r].rlim_cur != RLIM_INFINITY) {
			rlims[r].rlim_cur--;

			if (setrlimit(r, &rlims[r])) {
				err("Can't set rlimit");
				goto out;
			}

			changed = 1;
		}
	}

	if (!changed) {
		err("Can't change any rlimir");
		goto out;
	}

	test_daemon();
	test_waitsig();

	for (r = 0; r < RLIM_NLIMITS; r++) {
		if (getrlimit(r, &trlim)) {
			fail("Can't get rlimit after rst");
			goto out;
		}

		if (rlims[r].rlim_cur != trlim.rlim_cur) {
			fail("Cur changed");
			goto out;
		}

		if (rlims[r].rlim_max != trlim.rlim_max) {
			fail("Max changed");
			goto out;
		}
	}

	pass();
out:
	return 0;
}

