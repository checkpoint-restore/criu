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

const char *test_doc = "check that veth C/R-s right";
const char *test_author = "Pavel Emelyanov <xemul@virtuozzo.com>";

#define IF_NAME "zdtmvthc0"

static bool wait_for_veth(void)
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

	if (!wait_for_veth()) {
		fail("failed to inject veth device");
		return 1;
	}

	if (system("ip addr list dev " IF_NAME " | sed -e 's/@.*://' > cr_veth.dump.state")) {
		fail("can't save net config");
		goto out;
	}

	test_daemon();
	test_waitsig();

	if (system("ip addr list dev " IF_NAME " | sed -e 's/@.*://' > cr_veth.rst.state")) {
		fail("can't get net config");
		goto out;
	}

	if (system("diff cr_veth.rst.state cr_veth.dump.state")) {
		fail("Net config differs after restore");
		goto out;
	}

	pass();
	ret = 0;

out:
	return ret;
}
