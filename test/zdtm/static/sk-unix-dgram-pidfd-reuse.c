#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include "zdtmtst.h"
#include "zdtm_pidfd.h"
#include "sysctl.h"

const char *test_doc = "Check a reaped sender stays dead when its pid is reused in the tree\n";
const char *test_author = "Ahmed Elaidy <elaidya225@gmail.com>";

/*
 * A sender queues a packet and is reaped, then a live task in the dumped tree
 * is made to take over its pid number:
 *
 *   sender P (pid N)  --> packet in sk[1], P exits and is reaped
 *   helper   (pid N)  --> alive, dumped and restored with the rest of the tree
 *
 * The packet's SCM_CREDENTIALS carries N, so looking N up in the dumped tree
 * hits the helper, which never sent anything. Only the pidfd knows better:
 * the struct pid the skb holds a reference on is reaped, a different struct
 * pid that happens to share the number. So the restored receiver must still
 * get a stale pidfd, not one of the live helper.
 *
 * Pid numbers are reused all the time on a long-running host, and nothing
 * about this needs the sender and the helper to be related.
 */

/*
 * Set up the whole thing: a packet from a reaped sender in @sk, and a live
 * child holding that sender's pid. Retried a few times because the pid we
 * asked for can be taken by an unrelated fork on a busy host, which leaves
 * nothing to test rather than something to fail on.
 *
 * Returns 1 on success, 0 if it could not be arranged, -1 on error.
 */
static int setup(int sk[2], pid_t *helper)
{
	int opt = 1, i;

	for (i = 0; i < 5; i++) {
		pid_t dead, child;

		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sk) < 0)
			return pr_perror("socketpair");

		if (setsockopt(sk[1], SOL_SOCKET, SO_PASSPIDFD, &opt, sizeof(opt)) < 0) {
			pr_perror("setsockopt SO_PASSPIDFD");
			goto err;
		}

		dead = zdtm_queue_msg_from_dead_child(&sk[0], 1, 42, 0, NULL);
		if (dead < 0)
			goto err;

		/* Ask the kernel to hand @dead out to the next task we fork. */
		if (sysctl_write_int("/proc/sys/kernel/ns_last_pid", dead - 1))
			goto drop;

		child = fork();
		if (child < 0) {
			pr_perror("fork");
			goto err;
		}
		if (child == 0) {
			/* Alive across the dump, killed by the parent at the end. */
			test_waitsig();
			_exit(0);
		}

		if (child == dead) {
			*helper = child;
			return 1;
		}

		test_msg("pid %d went to someone else, retrying\n", dead);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
	drop:
		close(sk[0]);
		close(sk[1]);
	}

	return 0;

err:
	close(sk[0]);
	close(sk[1]);
	return -1;
}

int main(int argc, char *argv[])
{
	int sk[2], pidfd, ec, rc, ret = 1;
	pid_t helper = -1;
	int status;

	test_init(argc, argv);

	rc = setup(sk, &helper);
	if (rc <= 0) {
		test_daemon();
		test_waitsig();
		if (rc < 0) {
			fail("can't set up a packet from a reaped sender");
			return 1;
		}
		skip("Test requires reusing the sender's pid, skipping...");
		pass();
		return 0;
	}

	/*
	 * The ground truth: the kernel itself must already treat the sender as
	 * gone, even though a live task now answers to its number. A pidfd it
	 * refuses to mint says so, and so does one that reports an exit.
	 */
	if (zdtm_recv_pidfd(sk[1], MSG_PEEK, &pidfd))
		goto out_kill;

	if (pidfd >= 0) {
		if (zdtm_pidfd_send_signal(pidfd, 0, NULL, 0) == 0 || errno != ESRCH) {
			close(pidfd);
			pr_err("kernel: the reaped sender's pidfd is not stale before the dump\n");
			goto out_kill;
		}
		close(pidfd);
	}

	test_daemon();
	test_waitsig();

	if (zdtm_recv_pidfd(sk[1], 0, &pidfd)) {
		fail("no SCM_PIDFD cmsg after restore");
		goto out_kill;
	}

	if (pidfd < 0) {
		/*
		 * A kernel that mints no pidfd for a reaped sender, which is
		 * the same answer it gave before the dump. Had the packet been
		 * credited to the live helper there would be a pidfd here.
		 */
		test_msg("kernel can't mint pidfds of reaped senders, got %d as before dump\n", pidfd);
		goto out_pass;
	}

	if (zdtm_pidfd_send_signal(pidfd, 0, NULL, 0) == 0 || errno != ESRCH) {
		close(pidfd);
		fail("restored pidfd is alive, the packet was credited to the reused pid");
		goto out_kill;
	}

	if (zdtm_pidfd_get_pid(pidfd) != -1) {
		close(pidfd);
		fail("restored pidfd fdinfo Pid is not -1");
		goto out_kill;
	}

	if (zdtm_pidfd_query_exit(pidfd, &ec) == 1 &&
	    (!WIFEXITED(ec) || WEXITSTATUS(ec) != 42)) {
		close(pidfd);
		fail("restored pidfd reports exit status %#x, expected exit 42", ec);
		goto out_kill;
	}

	close(pidfd);
out_pass:
	/*
	 * The verdict is only good once the helper that held the reused pid
	 * has been accounted for, so reap it before saying anything.
	 */
	kill(helper, SIGTERM);
	if (waitpid(helper, &status, 0) != helper || !WIFEXITED(status) || WEXITSTATUS(status)) {
		fail("the helper holding the reused pid did not exit cleanly");
		goto out;
	}

	ret = 0;
	pass();
out:
	close(sk[0]);
	close(sk[1]);
	return ret;

out_kill:
	kill(helper, SIGKILL);
	waitpid(helper, NULL, 0);
	close(sk[0]);
	close(sk[1]);
	return ret;
}
