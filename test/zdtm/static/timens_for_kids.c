#include <sys/types.h>
#include <sys/wait.h>
#include <sched.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#include "zdtmtst.h"

const char *test_doc	= "Check nested time namespaces";
const char *test_author	= "Andrei Vagin <avagin@gmail.com";


#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME   0x00000080
#endif

int main(int argc, char **argv)
{
	test_init(argc, argv);

	if (unshare(CLONE_NEWTIME)) {
		pr_perror("unshare");
		return 1;
	}


	test_daemon();
	test_waitsig();

	pass();

	return 0;
}
