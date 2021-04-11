#include "zdtmtst.h"

const char *test_doc = "static test for UDP socket\n";
const char *test_author = "Pavel Emelyanov <xemul@parallels.com<>\n";

/* Description:
 * Create two udp sockets, client sends corked message to server,
 * and will send another one after migration,
 * server shuold read the corked datagrams in one packet after migration
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
#include <arpa/inet.h>  /* for sockaddr_in and inet_ntoa() */
#include <sys/wait.h>
#include <netinet/udp.h>

static int port = 8880;
static char buf[11];

#define MSG1 "msg1"
#define MSG2 "msg_2"
#define MSG "msg1\0msg_2"

int main(int argc, char **argv)
{
	int ret, server_sk, client_sk;
	socklen_t len = sizeof(struct sockaddr_in);
	struct sockaddr_in server_addr, client_addr, addr;
	int opt;

	test_init(argc, argv);

	server_sk = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP); 
	if (server_sk < 0) {
		pr_perror("Can't create socket");
		return 1;
	}

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	server_addr.sin_port = htons(port);

	ret = bind(server_sk, (struct sockaddr *)&server_addr, len);
	if (ret < 0) {
		pr_perror("Can't bind socket");
		return 1;
	}

	client_sk = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP); 
	if (client_sk < 0) {
		pr_perror("Can't create socket");
		return 1;
	}

	memset(&client_addr, 0, sizeof(client_addr));
	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	client_addr.sin_port = htons(port + 1);

	ret = bind(client_sk, (struct sockaddr *)&client_addr, len);
	if (ret < 0) {
		pr_perror("Can't bind socket");
		return 1;
	}
	
	ret = connect(client_sk, (struct sockaddr *)&server_addr, len);
	if (ret < 0) {
		pr_perror("Can't connect");
		return 1;
	}

	opt = 1; // enable corked
	if (setsockopt(client_sk, SOL_UDP, UDP_CORK, &opt, sizeof(opt))) {
		pr_perror("Unable to set UDP_CORK");
		return 1;
	}

	if (send(client_sk, MSG1, sizeof(MSG1), 0) != sizeof(MSG1)) {
		pr_perror("write");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (send(client_sk, MSG2, sizeof(MSG2), 0) != sizeof(MSG2)) {
		pr_perror("write");
		return 1;
	}

	opt = 0; // diable corked
	if (setsockopt(client_sk, SOL_UDP, UDP_CORK, &opt, sizeof(opt))) {
		pr_perror("Unable to set UDP_CORK");
		return 1;
	}

	ret = recvfrom(server_sk, buf, sizeof(buf), 0,
			(struct sockaddr *)&addr, &len);
	if (ret <= 0) {
		fail("Can't recv");
		return 1;
	}

	if (len != sizeof(struct sockaddr_in) || memcmp(&client_addr, &addr, len)) {
		fail("Wrong peer");
		return 1;
	}

	if (ret != sizeof(MSG1) + sizeof(MSG2) || memcmp(buf, MSG, sizeof(MSG))) {
		fail("Wrong message");
		return 1;
	}

	pass();
	return 0;
}
