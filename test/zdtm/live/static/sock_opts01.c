#include <stdio.h>
#include <string.h>
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
	int sock, ret;
	char dev[IFNAMSIZ], dev2[IFNAMSIZ];
	socklen_t len, len2;

	test_init(argc, argv);

	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		pr_perror("can't create socket");
		return 1;
	}

	ret = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 5);
	if (ret < 0)
		ret = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3);
	if (ret < 0) {
		pr_perror("can't bind to eth0");
		return 1;
	}

	len = sizeof(dev);
	ret = getsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &dev, &len);
	if (ret < 0) {
		pr_perror("can't get dev binding");
		return 1;
	}

	test_daemon();
	test_waitsig();

	len2 = sizeof(dev);
	ret = getsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &dev2, &len2);
	if (ret < 0) {
		fail("can't get dev binding2");
		return 1;
	}

	if ((len != len2) || strncmp(dev, dev2, len))
		fail("wrong bound device");
	else
		pass();

	close(sock);

	return 0;
}
