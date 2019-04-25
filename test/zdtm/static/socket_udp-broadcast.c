#include <sys/socket.h>
#include <sys/types.h>

#include "zdtmtst.h"

const char *test_doc = "test checkpoint/restore of SO_BROADCAST\n";
const char *test_author = "Radostin Stoyanov <rstoyanov1@gmail.com>\n";

/* Description:
 * Create UDP socket, set SO_BROADCAST and verify its value after restore.
 */

int main(int argc, char **argv)
{
	int sockfd;
	int val;
	socklen_t len = sizeof(val);

	test_init(argc, argv);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		pr_perror("Can't create socket");
		return 1;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &(int){ 1 }, len)) {
		pr_perror("setsockopt");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (getsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &val, &len)) {
		pr_perror("getsockopt");
		return 1;
	}

	if (len != sizeof(val) || val != 1) {
		fail("SO_BROADCAST not set");
		return 1;
	}

	pass();
	return 0;
}
