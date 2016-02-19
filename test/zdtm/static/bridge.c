#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <linux/limits.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "zdtmtst.h"

const char *test_doc	= "check that empty bridges are c/r'd correctly";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

#define BRIDGE_NAME "zdtmbr0"

int add_bridge(void)
{
	if (system("ip link add " BRIDGE_NAME " type bridge"))
		return -1;

	if (system("ip addr add 10.0.55.55/32 dev " BRIDGE_NAME))
		return -1;

	/* use a link local address so we can test scope_id change */
	if (system("ip addr add fe80:4567::1/64 nodad dev " BRIDGE_NAME))
		return -1;

	if (system("ip link set " BRIDGE_NAME " up"))
		return -1;

	return 0;
}

int del_bridge(void)
{
	/* don't check for errors, let's try to make sure it's deleted */
	system("ip link set " BRIDGE_NAME " down");

	if (system("ip link del " BRIDGE_NAME))
		return -1;

	return 0;
}

int main(int argc, char **argv)
{
	int ret = 1;
	struct sockaddr_in6 addr;
	int sk;

	test_init(argc, argv);

	if (add_bridge() < 0)
		return 1;

	sk = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sk < 0) {
		fail("can't get socket");
		goto out;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin6_port = htons(0);
	addr.sin6_family = AF_INET6;
	if (inet_pton(AF_INET6, "fe80:4567::1", &addr.sin6_addr) < 0) {
		fail("can't convert inet6 addr");
		goto out;
	}
	addr.sin6_scope_id = if_nametoindex(BRIDGE_NAME);

	if (bind(sk, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		fail("can't bind");
		goto out;
	}

	/* Here, we grep for inet because some of the IPV6 DAD stuff can be
	 * racy, and all we really care about is that the bridge got restored
	 * with the right MAC, since we know DAD will succeed eventually.
	 *
	 * (I got this race with zdtm.py, but not with zdtm.sh; not quite sure
	 * what the environment difference is/was.)
	 */
	if (system("ip addr list dev " BRIDGE_NAME " | grep inet | sort > bridge.dump.test")) {
		pr_perror("can't save net config");
		fail("Can't save net config");
		goto out;
	}

	test_daemon();
	test_waitsig();

	if (system("ip addr list dev " BRIDGE_NAME " | grep inet | sort > bridge.rst.test")) {
		fail("Can't get net config");
		goto out;
	}

	if (system("diff bridge.rst.test bridge.dump.test")) {
		fail("Net config differs after restore");
		goto out;
	}

	pass();

	ret = 0;

out:
	del_bridge();
	return ret;
}
