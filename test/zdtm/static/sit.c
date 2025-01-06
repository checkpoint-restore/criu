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

const char *test_doc = "check sit devices";
const char *test_author = "Pavel Emelyanov <xemul@virtuozzo.com>";

#define IF_NAME	   "zdtmsit0"
#define LOCAL_ADDR "1.1.1.2"
#define REMOT_ADDR "2.2.2.1"

int main(int argc, char **argv)
{
	int ret = 1;

	test_init(argc, argv);

	if (system("ip link add " IF_NAME " type sit ttl 13 local " LOCAL_ADDR " remote " REMOT_ADDR)) {
		pr_perror("Can't make sit device");
		return 1;
	}

	if (system("ip -details addr list dev " IF_NAME " > sit.dump.test")) {
		fail("can't save net config");
		goto out;
	}

	test_daemon();
	test_waitsig();

	if (system("ip -details addr list dev " IF_NAME " > sit.rst.test")) {
		fail("can't get net config");
		goto out;
	}

	if (system("diff sit.rst.test sit.dump.test")) {
		fail("Net config differs after restore");
		goto out;
	}

	pass();
	ret = 0;

out:
	return ret;
}
