#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include "zdtmtst.h"
#include "zdtm_pidfd.h"

const char *test_doc = "Check restored pidfds of dead senders keep their identity\n";
const char *test_author = "Ahmed Elaidy <elaidya225@gmail.com>";

/*
 * A struct pid is identified by its pidfs inode number, not by how the process
 * died: since Linux 6.9 two pidfds compare equal exactly when their inode
 * numbers do, and that is the only handle userspace has on the identity of a
 * process that has already been reaped.
 *
 * This test builds three packets whose senders all died the very same way,
 * plus a pidfd held on one of those senders, and checks that C/R preserves
 * which of them are the same struct pid and which are not:
 *
 *   packet 1  <- sender B, exit 42, and we hold a pidfd of B
 *   packet 2  <- sender A1, exit 42
 *   packet 3  <- sender A2, exit 42
 *
 * so afterwards ino(held) == ino(packet 1), and ino(packet 2) != ino(packet 3).
 */

/* As zdtm_recv_pidfd(), but also demand a usable pidfd and return its pidfs ino. */
static int recv_pidfd_ino(int sk_rcv, int flags, uint64_t *ino, int *exit_code)
{
	int pidfd, ret;

	if (zdtm_recv_pidfd(sk_rcv, flags, &pidfd))
		return -1;

	if (pidfd < 0) {
		pr_err("no pidfd in cmsg: %d\n", pidfd);
		return -1;
	}

	ret = zdtm_pidfs_ino(pidfd, ino);
	if (!ret && exit_code && zdtm_pidfd_query_exit(pidfd, exit_code) != 1) {
		pr_err("PIDFD_GET_INFO does not report an exit status\n");
		ret = -1;
	}

	close(pidfd);
	return ret;
}

/*
 * Establish what this kernel does, on a throwaway socketpair, before the dump
 * decides anything. Only kernels >= 6.17 mint a pidfd for a sender that has
 * already been reaped; without one there is no identity to observe and nothing
 * for this test to check. *exit_info is set when PIDFD_GET_INFO also reports
 * the sender's exit status.
 *
 * Returns 1 if the test can run, 0 if it must be skipped, -1 on error.
 */
static int probe_kernel(int *exit_info)
{
	uint64_t ino_held, ino_1, ino_2;
	int sk[2], held = -1, pidfd;
	int opt = 1, ec;

	*exit_info = 0;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sk) < 0)
		return pr_perror("socketpair");

	if (setsockopt(sk[1], SOL_SOCKET, SO_PASSPIDFD, &opt, sizeof(opt)) < 0) {
		pr_perror("setsockopt SO_PASSPIDFD");
		goto err;
	}

	if (zdtm_queue_msg_from_dead_child(&sk[0], 1, 42, 0, &held) < 0)
		goto err;
	if (zdtm_queue_msg_from_dead_child(&sk[0], 1, 42, 0, NULL) < 0)
		goto err;

	/* Peek first: a kernel that can't mint the pidfd is a skip, not a failure. */
	if (zdtm_recv_pidfd(sk[1], MSG_PEEK, &pidfd))
		goto err;

	if (pidfd < 0) {
		test_msg("kernel can't mint pidfds of reaped senders (%d), skipping\n", pidfd);
		close(held);
		close(sk[0]);
		close(sk[1]);
		return 0;
	}
	close(pidfd);

	if (zdtm_pidfs_ino(held, &ino_held))
		goto err;
	if (recv_pidfd_ino(sk[1], 0, &ino_1, NULL))
		goto err;
	if (recv_pidfd_ino(sk[1], 0, &ino_2, NULL))
		goto err;

	/*
	 * The ground truth this test is built on. If the kernel does not hold
	 * to it there is no point checking that C/R preserves it.
	 */
	if (ino_held != ino_1) {
		pr_err("kernel: held pidfd and queued packet of one sender differ: %llu vs %llu\n",
		       (unsigned long long)ino_held, (unsigned long long)ino_1);
		goto err;
	}
	if (ino_1 == ino_2) {
		pr_err("kernel: two distinct senders share pidfs ino %llu\n",
		       (unsigned long long)ino_1);
		goto err;
	}

	if (zdtm_pidfd_query_exit(held, &ec) == 1 && WIFEXITED(ec) && WEXITSTATUS(ec) == 42)
		*exit_info = 1;

	close(held);
	close(sk[0]);
	close(sk[1]);
	return 1;

err:
	if (held >= 0)
		close(held);
	close(sk[0]);
	close(sk[1]);
	return -1;
}

int main(int argc, char *argv[])
{
	uint64_t ino_held, ino_1, ino_2, ino_3;
	int sk[2], held = -1, peeked;
	int opt = 1, ready, exit_info;
	int ec1 = 0, ec2 = 0, ec3 = 0;

	test_init(argc, argv);

	if (zdtm_has_pidfs() != 1) {
		test_daemon();
		test_waitsig();
		skip("Test requires pidfs, skipping...");
		pass();
		return 0;
	}

	ready = probe_kernel(&exit_info);
	if (ready < 0)
		return 1;
	if (ready == 0) {
		test_daemon();
		test_waitsig();
		skip("Test requires a kernel that mints pidfds of reaped senders, skipping...");
		pass();
		return 0;
	}

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sk) < 0)
		return pr_perror("socketpair");

	if (setsockopt(sk[1], SOL_SOCKET, SO_PASSPIDFD, &opt, sizeof(opt)) < 0)
		return pr_perror("setsockopt SO_PASSPIDFD");

	/*
	 * Three senders that all exit 42, so nothing but the struct pid tells
	 * them apart. We keep a pidfd of the first one, whose packet is at the
	 * head of the queue and can therefore be peeked before the dump.
	 */
	if (zdtm_queue_msg_from_dead_child(&sk[0], 1, 42, 0, &held) < 0)
		return 1;
	if (zdtm_queue_msg_from_dead_child(&sk[0], 1, 42, 0, NULL) < 0)
		return 1;
	if (zdtm_queue_msg_from_dead_child(&sk[0], 1, 42, 0, NULL) < 0)
		return 1;

	if (zdtm_pidfs_ino(held, &ino_held))
		return 1;
	if (zdtm_recv_pidfd(sk[1], MSG_PEEK, &peeked))
		return 1;
	if (peeked < 0) {
		pr_err("no pidfd in cmsg before dump: %d\n", peeked);
		return 1;
	}
	if (zdtm_pidfs_ino(peeked, &ino_1)) {
		close(peeked);
		return 1;
	}
	close(peeked);

	if (ino_held != ino_1) {
		pr_err("before dump: held pidfd %llu != queued pidfd %llu\n",
		       (unsigned long long)ino_held, (unsigned long long)ino_1);
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (zdtm_pidfs_ino(held, &ino_held)) {
		fail("can't stat the restored pidfd");
		return 1;
	}

	if (recv_pidfd_ino(sk[1], 0, &ino_1, exit_info ? &ec1 : NULL) ||
	    recv_pidfd_ino(sk[1], 0, &ino_2, exit_info ? &ec2 : NULL) ||
	    recv_pidfd_ino(sk[1], 0, &ino_3, exit_info ? &ec3 : NULL)) {
		fail("can't get the pidfds of the restored packets");
		return 1;
	}

	/*
	 * The pidfd we hold and the first packet came from one and the same
	 * sender, so restore must not stand in for it twice.
	 */
	if (ino_held != ino_1) {
		fail("restored pidfd %llu and its queued packet %llu are no longer the same process",
		     (unsigned long long)ino_held, (unsigned long long)ino_1);
		return 1;
	}

	/*
	 * These three senders were three processes. Restore may not collapse
	 * them into one just because they died the same way.
	 */
	if (ino_1 == ino_2 || ino_1 == ino_3 || ino_2 == ino_3) {
		fail("distinct senders share a pidfs ino after restore: %llu %llu %llu",
		     (unsigned long long)ino_1, (unsigned long long)ino_2,
		     (unsigned long long)ino_3);
		return 1;
	}

	if (exit_info) {
		if (!WIFEXITED(ec1) || WEXITSTATUS(ec1) != 42 ||
		    !WIFEXITED(ec2) || WEXITSTATUS(ec2) != 42 ||
		    !WIFEXITED(ec3) || WEXITSTATUS(ec3) != 42) {
			fail("restored pidfds do not all report exit code 42");
			return 1;
		}
	}

	close(held);
	close(sk[0]);
	close(sk[1]);

	pass();
	return 0;
}
