#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "zdtmtst.h"

const char *test_doc	= "Create a socket before migration, and bind to it after\n";
const char *test_author	= "Roman Kagan <rkagan@parallels.com>";

#define TEST_PORT 59687
#define TEST_ADDR INADDR_ANY

int main(int argc, char ** argv)
{
	int sock;
	struct sockaddr_in name = {
		.sin_family		= AF_INET,
		.sin_port		= htons(TEST_PORT),
		.sin_addr.s_addr	= htonl(TEST_ADDR),
	};

	test_init(argc, argv);

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		pr_perror("can't create socket");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (bind(sock, (struct sockaddr *) &name, sizeof(name)) < 0)
		fail("can't bind to a socket: %m");
	else
		pass();

	close(sock);
	return 0;
}
