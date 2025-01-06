#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc = "Check that a signal handler for SIGTRAP is restored";
const char *test_author = "Andrei Vagin <avagin@gmail.com>";

static int sigtrap = 0;
static void sigh(int signo)
{
	sigtrap = 1;
}

int main(int argc, char **argv)
{
	test_init(argc, argv);

	signal(SIGTRAP, sigh);

	test_daemon();
	test_waitsig();
	kill(getpid(), SIGTRAP);

	if (sigtrap != 1) {
		fail("The sigtrap handler hasn't been called.");
		return 1;
	}

	pass();
	return 0;
}
