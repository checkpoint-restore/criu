#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that SO_BINDTODEVICE option works";
const char *test_author	= "Pavel Emelyanov <xemul@parallels.com>";

int main(int argc, char ** argv)
{
	int sock, ret, dev, dev2;
	socklen_t len = sizeof(dev);

	test_init(argc, argv);

	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		err("can't create socket: %m");
		return 1;
	}

	ret = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 5);
	if (ret < 0)
		ret = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3);
	if (ret < 0) {
		err("can't bind to eth0");
		return 1;
	}

	ret = getsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &dev, &len);
	if (ret < 0) {
		err("can't get dev binding");
		return 1;
	}

	test_daemon();
	test_waitsig();

	ret = getsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &dev2, &len);
	if (ret < 0) {
		fail("can't get dev binding2");
		return 1;
	}

	if (!dev2)
		fail("unbound sock restored");
	else if (dev != dev2)
		fail("wrong bound device");
	else
		pass();

	close(sock);

	return 0;
}
