#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <linux/limits.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "zdtmtst.h"

const char *test_doc = "check that macvlan interfaces are c/r'd correctly";
const char *test_author = "Tycho Andersen <tycho.andersen@canonical.com>";

#define BRIDGE_NAME "zdtmbr0"
#define IF_NAME	    "zdtmmvlan0"

static bool wait_for_macvlan(void)
{
	int i;

	for (i = 0; i < 10; i++) {
		if (system("ip addr list dev " IF_NAME) == 0)
			return true;

		sleep(1);
	}

	return false;
}

int main(int argc, char **argv)
{
	int ret = 1;

	test_init(argc, argv);

	if (!wait_for_macvlan()) {
		fail("failed to inject macvlan device");
		return 1;
	}

	if (system("ip addr list dev " IF_NAME " > macvlan.dump.test")) {
		fail("can't save net config");
		goto out;
	}

	test_daemon();
	test_waitsig();

	if (system("ip addr list dev " IF_NAME " > macvlan.rst.test")) {
		fail("can't get net config");
		goto out;
	}

	if (system("diff macvlan.rst.test macvlan.dump.test")) {
		fail("Net config differs after restore");
		goto out;
	}

	pass();
	ret = 0;

out:
	return ret;
}
