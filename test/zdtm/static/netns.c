#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc = "Check that network environment (links, addresses and routes) are preserved";
const char *test_author = "Pavel Emelianov <xemul@parallels.com>";

int main(int argc, char **argv)
{
	test_init(argc, argv);

	if (system("ip link set lo up")) {
		fail("Can't set lo up");
		return -1;
	}

	if (system("ip addr add 1.2.3.4 dev lo")) {
		fail("Can't add addr on lo");
		return -1;
	}

	if (system("ip route add 1.2.3.5 dev lo")) {
		fail("Can't add route via lo");
		return -1;
	}

	if (system("ip route add 1.2.3.6 via 1.2.3.5")) {
		fail("Can't add route via lo (2)");
		return -1;
	}

	if (system("ip link > netns.dump.test && ip addr >> netns.dump.test && ip route >> netns.dump.test")) {
		sleep(1000);
		fail("Can't save net config");
		return -1;
	}

	test_daemon();
	test_waitsig();

	if (system("ip link > netns.rst.test && ip addr >> netns.rst.test && ip route >> netns.rst.test")) {
		fail("Can't get net config");
		return -1;
	}

	if (system("diff netns.rst.test netns.dump.test")) {
		fail("Net config differs after restore");
		return -1;
	}

	pass();
	return 0;
}
