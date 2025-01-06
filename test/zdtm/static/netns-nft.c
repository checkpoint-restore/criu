#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "zdtmtst.h"

const char *test_doc = "Check that nft rules (some) are kept";
const char *test_author = "Alexander Mikhalitsyn <alexander@mihalicyn.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

int main(int argc, char **argv)
{
	char cmd[128];

	test_init(argc, argv);

	/* create nft table */
	if (system("nft add table inet netns-nft-zdtm-test")) {
		pr_perror("Can't create nft table");
		return -1;
	}

	/* create input chain in table */
	if (system("nft add chain inet netns-nft-zdtm-test input { type filter hook input priority 0 \\; }")) {
		pr_perror("Can't create input chain in nft table");
		return -1;
	}

	/* block ICMPv4 traffic */
	if (system("nft add rule inet netns-nft-zdtm-test input meta nfproto ipv4 icmp type { echo-request } reject")) {
		pr_perror("Can't set input rule");
		return -1;
	}

	/* save resulting nft table */
	sprintf(cmd, "nft list table inet netns-nft-zdtm-test > pre-%s", filename);
	if (system(cmd)) {
		pr_perror("Can't get nft table");
		return -1;
	}

	test_daemon();
	test_waitsig();

	/* get nft table */
	sprintf(cmd, "nft list table inet netns-nft-zdtm-test > post-%s", filename);
	if (system(cmd)) {
		fail("Can't get nft table");
		return -1;
	}

	/* compare nft table before/after c/r */
	sprintf(cmd, "diff pre-%s post-%s", filename, filename);
	if (system(cmd)) {
		fail("nft table differ");
		return -1;
	}

	pass();
	return 0;
}
