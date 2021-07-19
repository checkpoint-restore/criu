#include "zdtmtst.h"

#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <unistd.h>
#include <fcntl.h>

const char *test_doc = "Check bound and not bound SOCK_PACKET sockets";
const char *test_author = "Gleb Valin <the7winds@yandex.ru>";

struct ethframe {
	struct ethhdr header;
	char data[ETH_DATA_LEN];
};

static int do_bind(int sk)
{
	struct sockaddr addr = {};

	addr.sa_family = AF_PACKET;
	strcpy(addr.sa_data, "lo");

	return bind(sk, (struct sockaddr *)&addr, sizeof(addr));
}

static int check_socket_binding(int sk, char *dev)
{
	struct sockaddr addr = {};

	socklen_t l = sizeof(addr);

	if (getsockname(sk, &addr, &l) < 0)
		return -1;

	if (addr.sa_family != AF_PACKET)
		return -1;

	if (strcmp(addr.sa_data, dev) != 0)
		return -1;

	return 0;
}

int main(int argc, char **argv)
{
	int sk1;
	int sk2;

	test_init(argc, argv);

	sk1 = socket(AF_PACKET, SOCK_PACKET, htons(ETH_P_ALL));

	if (sk1 < 0) {
		pr_perror("Can't create socket 1");
		return 1;
	}

	if (do_bind(sk1) < 0) {
		pr_perror("Can't bind sosket 1");
		return 1;
	}

	sk2 = socket(AF_PACKET, SOCK_PACKET, htons(ETH_P_ALL));

	if (sk2 < 0) {
		pr_perror("Can't create socket 2");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (check_socket_binding(sk1, "lo") < 0) {
		fail("Socket 1 has wrong binding");
		return 1;
	}

	if (check_socket_binding(sk2, "") < 0) {
		fail("Socket 2 has wrong binding");
		return 1;
	}

	pass();
	return 0;
}
