#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc	= "Test unix sockets shutdown";
const char *test_author	= "Pavel Emelyanov <xemul@parallels.com>";

#define fin(msg)	do { pr_perror(msg); exit(1); } while (0)
#define ffin(msg)	do { fail(msg); exit(1); } while (0)

#define TEST_MSG	"test-message"
static char buf[sizeof(TEST_MSG)];

int main(int argc, char *argv[])
{
	int spu[2], spb[2], dpu[2], dpb[2], dpd[2];
	int ret;

	test_init(argc, argv);

	signal(SIGPIPE, SIG_IGN);

	/* spu -- stream pair, unidirectional shutdown */
	if (socketpair(PF_UNIX, SOCK_STREAM, 0, spu) < 0)
		fin("no stream pair 1");

	if (shutdown(spu[0], SHUT_RD) < 0)
		fin("no stream shutdown 1");

	/* spb -- stream pair, bidirectional shutdown */
	if (socketpair(PF_UNIX, SOCK_STREAM, 0, spb) < 0)
		fin("no stream pair 2");

	if (shutdown(spb[0], SHUT_RDWR) < 0)
		fin("no stream shutdown 2");

	/* dpu -- dgram pair, one end read shutdown */
	if (socketpair(PF_UNIX, SOCK_DGRAM, 0, dpu) < 0)
		fin("no dgram pair 1");

	if (shutdown(dpu[0], SHUT_RD) < 0)
		fin("no dgram shutdown 1");

	/* dpb -- dgram pair, one end read-write shutdown */
	if (socketpair(PF_UNIX, SOCK_DGRAM, 0, dpb) < 0)
		fin("no dgram pair 2");

	if (shutdown(dpb[0], SHUT_RDWR) < 0)
		fin("no dgram shutdown 2");

	/* dpd -- dgram pair, one end write shutdown with data */
	if (socketpair(PF_UNIX, SOCK_DGRAM, 0, dpd) < 0)
		fin("no dgram pair 3");

	if (write(dpd[0], TEST_MSG, sizeof(TEST_MSG)) < 0)
		fin("no dgram write");

	if (shutdown(dpd[0], SHUT_WR) < 0)
		fin("no dgram shutdown 3");

	test_daemon();
	test_waitsig();

	/*
	 * spu -- check that one direction is blocked and
	 * the other one is not
	 */

	ret = write(spu[0], TEST_MSG, sizeof(TEST_MSG));
	if (ret < 0)
		ffin("SU shutdown broken 1");

	ret = read(spu[1], buf, sizeof(buf));
	if (ret < 0)
		ffin("SU shutdown broken 2");

	ret = write(spu[1], TEST_MSG, sizeof(TEST_MSG));
	if (ret >= 0)
		ffin("SU shutdown broken 3");

	/*
	 * spb -- check that both ends are off
	 */

	ret = write(spb[0], TEST_MSG, sizeof(TEST_MSG));
	if (ret >= 0)
		ffin("SB shutdown broken 1");

	ret = write(spb[1], TEST_MSG, sizeof(TEST_MSG));
	if (ret >= 0)
		ffin("SB shutdown broken 2");

	/*
	 * dpu -- check that one direction works, and
	 * the other does not
	 */

	ret = write(dpu[0], TEST_MSG, sizeof(TEST_MSG));
	if (ret < 0)
		ffin("DU shutdown broken 1");

	ret = read(dpu[1], buf, sizeof(buf));
	if (ret < 0)
		ffin("DU shutdown broken 2");

	ret = write(dpu[1], TEST_MSG, sizeof(TEST_MSG));
	if (ret >= 0)
		ffin("DU shutdown broken 3");

	/*
	 * dpb -- check that both ends are read
	 */

	ret = write(dpb[0], TEST_MSG, sizeof(TEST_MSG));
	if (ret >= 0)
		ffin("DB shutdown broken 1");

	ret = write(dpb[1], TEST_MSG, sizeof(TEST_MSG));
	if (ret >= 0)
		ffin("DB shutdown broken 2");

	/*
	 * dpd -- check that data is in there, but can't
	 * feed more
	 */

	ret = read(dpd[1], buf, sizeof(buf));
	if (ret < 0)
		ffin("DD shutdown nodata");

	ret = write(dpd[0], TEST_MSG, sizeof(buf));
	if (ret >= 0)
		ffin("DB shutdown broken");

	pass();
	return 0;
}
