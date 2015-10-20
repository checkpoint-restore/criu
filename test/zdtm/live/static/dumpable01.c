#include <sys/prctl.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc    = "Check dumpable flag handling (dumpable case)";
const char *test_author = "Filipe Brandenburger <filbranden@google.com>";

int main(int argc, char **argv)
{
	int save_dumpable;
	int dumpable;

	test_init(argc, argv);

	save_dumpable = prctl(PR_GET_DUMPABLE);
	if (save_dumpable < 0) {
		pr_perror("error getting prctl(PR_GET_DUMPABLE) before dump");
		return 1;
	}
#ifdef DEBUG
	test_msg("DEBUG: before dump: dumpable=%d\n", save_dumpable);
#endif

	/* Wait for criu dump and restore. */
	test_daemon();
	test_waitsig();

	dumpable = prctl(PR_GET_DUMPABLE);
	if (dumpable < 0) {
		pr_perror("error getting prctl(PR_GET_DUMPABLE) after restore");
		return 1;
	}
#ifdef DEBUG
	test_msg("DEBUG: after dump: dumpable=%d\n", dumpable);
#endif

	if (dumpable != save_dumpable) {
		errno = 0;
		fail("dumpable flag was not preserved over migration");
		return 1;
	}

	pass();
	return 0;
}
