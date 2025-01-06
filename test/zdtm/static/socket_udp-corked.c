#include "zdtmtst.h"

const char *test_doc = "static test for UDP socket\n";
const char *test_author = "Pavel Emelyanov <xemul@parallels.com<>\n";

/* Description:
 * Create two tcp socket, server send asynchronous request on
 * read data and client write data after migration
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h> /* for sockaddr_in and inet_ntoa() */
#include <sys/wait.h>
#include <netinet/udp.h>

static int port = 8880;

#define MSG1 "msg1"

int main(int argc, char **argv)
{
	int ret, sk1;
	socklen_t len = sizeof(struct sockaddr_in);
	struct sockaddr_in addr1;
	int opt;

	test_init(argc, argv);

	sk1 = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sk1 < 0) {
		pr_perror("Can't create socket");
		return 1;
	}

	memset(&addr1, 0, sizeof(addr1));
	addr1.sin_family = AF_INET;
	addr1.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr1.sin_port = htons(port);

	ret = bind(sk1, (struct sockaddr *)&addr1, len);
	if (ret < 0) {
		pr_perror("Can't bind socket");
		return 1;
	}
	ret = connect(sk1, (struct sockaddr *)&addr1, len);
	if (ret < 0) {
		pr_perror("Can't connect");
		return 1;
	}

	opt = 1;
	if (setsockopt(sk1, SOL_UDP, UDP_CORK, &opt, sizeof(opt))) {
		pr_perror("Unable to set UDP_CORK");
		return 1;
	}

	if (write(sk1, MSG1, sizeof(MSG1)) != sizeof(MSG1)) {
		pr_perror("write");
		return 1;
	}

	test_daemon();
	test_waitsig();

	pass();
	return 0;
}
