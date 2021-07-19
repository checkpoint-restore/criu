#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Restore with precreated veth devices.";
const char *test_author = "Andrei Vagin <avagin@gmail.com>";

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
	test_init(argc, argv);

	if (!wait_for_veth()) {
		fail("failed to inject veth device");
		return 1;
	}

	if (system("ip addr list dev " IF_NAME " | sed -e 's/@.*://' > cr_veth02.dump.state")) {
		fail("can't save net config");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (system("ip addr list dev " IF_NAME " | sed -e 's/@.*://' > cr_veth02.rst.state")) {
		fail("can't get net config");
		return 1;
	}

	if (system("diff cr_veth02.rst.state cr_veth02.dump.state")) {
		fail("Net config differs after restore");
		return 1;
	}

	pass();

	return 0;
}
