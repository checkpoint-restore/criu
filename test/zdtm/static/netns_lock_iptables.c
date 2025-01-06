#include "zdtmtst.h"

const char *test_doc = "Check network namespace is locked between dump and restore\n";
const char *test_author = "Zeyad Yasser <zeyady98@gmail.com>";

#include <errno.h>
#include <fcntl.h>
#include <sched.h>

#define NS_PATH	      "/var/run/netns/criu-net-lock-test"
#define SYNCFILE_PATH "net_lock.sync"
#define MAX_RETRY     3

int main(int argc, char **argv)
{
	int i, ns_fd;

	test_init(argc, argv);

	/*
	 * We try to enter the netns created by post-start hook so that
	 * criu locks the network namespace between dump and restore.
	 *
	 * A TCP server is started in post-start hook inside the netns
	 * and runs in the background detached from its parent so that
	 * it stays alive for the duration of the test.
	 *
	 * Other hooks (pre-dump, pre-restore, post-restore) try to
	 * connect to the server.
	 *
	 * Pre-dump and post-restore hooks should be able to connect
	 * successfully.
	 *
	 * Pre-restore hook client with SOCCR_MARK should also connect
	 * successfully.
	 *
	 * Pre-restore hook client without SOCCR_MARK should not be able
	 * to connect but also should not get connection refused as all
	 * packets are dropped in the namespace so the kernel shouldn't
	 * send an RST packet as a result. Instead we check that the
	 * connect operation causes a timeout.
	 */

	for (i = 0; i < MAX_RETRY; i++) {
		if (access(SYNCFILE_PATH, F_OK)) {
			/* Netns not created yet by post-start hook */
			sleep(1);
			continue;
		}
		break;
	}

	ns_fd = open(NS_PATH, O_RDONLY);
	if (ns_fd < 0) {
		pr_perror("can't open network ns");
		return 1;
	}

	if (setns(ns_fd, CLONE_NEWNET)) {
		pr_perror("setns %d", ns_fd);
		return 1;
	}

	close(ns_fd);

	test_daemon();
	test_waitsig();

	pass();

	return 0;
}
