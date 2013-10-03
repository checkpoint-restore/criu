#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that netfilter rules (some) are kept";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

static int test_fn(int argc, char **argv)
{
	char cmd[128];

	if (system("iptables -A INPUT -t filter --protocol icmp -j DROP")) {
		err("Can't set input rule");
		return -1;
	}

	sprintf(cmd, "iptables -L > pre-%s", filename);
	if (system(cmd)) {
		err("Can't save iptables");
		return -1;
	}

	test_daemon();
	test_waitsig();

	sprintf(cmd, "iptables -L > post-%s", filename);
	if (system(cmd)) {
		fail("Can't get iptables");
		return -1;
	}

	sprintf(cmd, "diff pre-%s post-%s", filename, filename);
	if (system(cmd)) {
		fail("Iptables differ");
		return -1;
	}

	pass();
	return 0;
}

#define CLONE_NEWNET     0x40000000

int main(int argc, char **argv)
{
	test_init_ns(argc, argv, CLONE_NEWNET, test_fn);
	return 0;
}

