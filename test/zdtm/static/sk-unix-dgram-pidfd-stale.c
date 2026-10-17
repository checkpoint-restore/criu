#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include "zdtmtst.h"
#include "zdtm_pidfd.h"

const char *test_doc = "Test C/R of a stale pidfd in unix socket queue (sender died before dump)\n";
const char *test_author = "Ahmed Elaidy <elaidya225@gmail.com>";

/*
 * Only kernels >= 6.17 can mint a pidfd for an already reaped process; older
 * ones put a negative error code into the cmsg payload instead. Probe which
 * behavior this kernel has, so we can check that C/R preserves it. When a
 * pidfd can be minted, also probe whether PIDFD_GET_INFO / PIDFD_INFO_EXIT
 * reports the sender's exit status; *exit_info is set to 1 if it does.
 *
 * Returns 1 if reaped pidfds are supported, 0 otherwise, -1 on error.
 */
static int probe_reaped_pidfd(int *exit_info)
{
	int sk[2];
	int opt = 1;
	int pidfd, ec;

	*exit_info = 0;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sk) < 0) {
		pr_perror("socketpair");
		return -1;
	}

	if (setsockopt(sk[1], SOL_SOCKET, SO_PASSPIDFD, &opt, sizeof(opt)) < 0) {
		pr_perror("setsockopt SO_PASSPIDFD");
		goto err;
	}

	/* Exit with a distinctive code we can look for via PIDFD_GET_INFO. */
	if (zdtm_queue_msg_from_dead_child(&sk[0], 1, 123, 0, NULL) < 0)
		goto err;

	if (zdtm_recv_pidfd(sk[1], 0, &pidfd))
		goto err;

	close(sk[0]);
	close(sk[1]);

	if (pidfd < 0)
		return 0;

	if (zdtm_pidfd_query_exit(pidfd, &ec) == 1 && WIFEXITED(ec) && WEXITSTATUS(ec) == 123)
		*exit_info = 1;

	close(pidfd);
	return 1;
err:
	close(sk[0]);
	close(sk[1]);
	return -1;
}

/* Check a restored packet yields a pidfd that is stale exactly as before dump. */
static int check_stale_pidfd(int sk_rcv, int reaped_pidfd_supported)
{
	int pidfd;

	if (zdtm_recv_pidfd(sk_rcv, 0, &pidfd)) {
		fail("no SCM_PIDFD cmsg after restore");
		return -1;
	}

	if (!reaped_pidfd_supported) {
		/*
		 * Pre-dump recvmsg would have failed to mint a pidfd for the
		 * dead sender the same way.
		 */
		if (pidfd >= 0) {
			close(pidfd);
			fail("got pidfd %d, but kernel can't mint pidfds of reaped processes", pidfd);
			return -1;
		}
		test_msg("kernel can't mint pidfds of reaped processes, got %d as before dump\n", pidfd);
		return -2; /* not a failure: no pidfd to inspect on this kernel */
	}

	if (pidfd < 0) {
		fail("invalid pidfd %d after restore", pidfd);
		return -1;
	}

	/* The pidfd must reference a dead process, as before the dump */
	if (zdtm_pidfd_send_signal(pidfd, 0, NULL, 0) == 0 || errno != ESRCH) {
		close(pidfd);
		fail("pidfd is not stale after restore");
		return -1;
	}

	if (zdtm_pidfd_get_pid(pidfd) != -1) {
		close(pidfd);
		fail("pidfd fdinfo Pid is not -1 after restore");
		return -1;
	}

	return pidfd;
}

/*
 * Check the next restored packet: its pidfd must be stale exactly as it was
 * before the dump and, on kernels that report exit info, must carry the status
 * its sender died with -- @exit_code when @term_sig is 0, death by @term_sig
 * otherwise.
 */
static int check_packet(int sk_rcv, int reaped_pidfd_supported, int exit_info_supported,
			int exit_code, int term_sig)
{
	int pidfd, ec;

	pidfd = check_stale_pidfd(sk_rcv, reaped_pidfd_supported);
	if (pidfd == -1)
		return -1;
	if (pidfd < 0) /* -2: nothing to inspect on this kernel */
		return 0;

	if (exit_info_supported) {
		if (zdtm_pidfd_query_exit(pidfd, &ec) != 1)
			goto err;
		if (term_sig) {
			if (!WIFSIGNALED(ec) || WTERMSIG(ec) != term_sig)
				goto err;
		} else if (!WIFEXITED(ec) || WEXITSTATUS(ec) != exit_code) {
			goto err;
		}
	}

	close(pidfd);
	return 0;
err:
	close(pidfd);
	if (term_sig)
		fail("restored pidfd does not report death by signal %d", term_sig);
	else
		fail("restored pidfd does not report exit code %d", exit_code);
	return -1;
}

int main(int argc, char *argv[])
{
	int sk[2];
	int opt = 1;
	int reaped_pidfd_supported;
	int exit_info_supported;

	test_init(argc, argv);

	reaped_pidfd_supported = probe_reaped_pidfd(&exit_info_supported);
	if (reaped_pidfd_supported < 0)
		return 1;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sk) < 0)
		return pr_perror("socketpair");

	if (setsockopt(sk[1], SOL_SOCKET, SO_PASSPIDFD, &opt, sizeof(opt)) < 0)
		return pr_perror("setsockopt SO_PASSPIDFD");

	/*
	 * Three stale packets. The first two senders died differently -- one
	 * exited with a code, one was killed by a signal -- so each must come
	 * back reporting its own status. The third died exactly like the
	 * first, which is what makes it interesting: dying the same way is not
	 * being the same process, so restore owes it a stand-in of its own
	 * rather than collapsing it onto the first one's.
	 */
	if (zdtm_queue_msg_from_dead_child(&sk[0], 1, 42, 0, NULL) < 0)
		return 1;
	if (zdtm_queue_msg_from_dead_child(&sk[0], 1, 0, SIGUSR1, NULL) < 0)
		return 1;
	if (zdtm_queue_msg_from_dead_child(&sk[0], 1, 42, 0, NULL) < 0)
		return 1;

	test_daemon();
	test_waitsig();

	if (check_packet(sk[1], reaped_pidfd_supported, exit_info_supported, 42, 0))
		return 1;
	if (check_packet(sk[1], reaped_pidfd_supported, exit_info_supported, 0, SIGUSR1))
		return 1;
	if (check_packet(sk[1], reaped_pidfd_supported, exit_info_supported, 42, 0))
		return 1;

	close(sk[0]);
	close(sk[1]);

	pass();
	return 0;
}
