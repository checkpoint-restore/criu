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

const char *test_doc = "Check a dead sender keeps one identity across two tasks\n";
const char *test_author = "Ahmed Elaidy <elaidya225@gmail.com>";

/*
 * One process sends a packet into two different unix sockets and dies. The
 * two sockets are then handed to two different tasks, one each, so that on
 * restore each of them is refilled by a different process: criu sends a
 * queued packet from the task that owns the sending end of the socket.
 *
 *   task A   sk1[0] --> sk1[1]   holds a packet from sender P
 *   task B   sk2[0] --> sk2[1]   holds a packet from sender P
 *
 * Both packets came from the one struct pid, so both receivers must mint a
 * pidfd with the same pidfs ino -- before the dump, and again after restore.
 *
 * What this pins down is that the stand-in process restore forks for a dead
 * sender is shared across tasks. The stand-ins are keyed on the pidfs ino in
 * one table built before the task tree is forked, and the root task forks
 * them, so both tasks here refill their queue from the one stand-in. A table
 * private to each restoring task would give two stand-ins and two inos.
 * Nothing here is exotic; it takes only two processes and one dead sender.
 */

/* What a task reports back about the packet it is holding. */
struct report {
	int ok;
	int have_exit;
	int exit_code;
	uint64_t ino;
};

/* As zdtm_recv_pidfd(), but also demand a usable pidfd and fill in the report. */
static int recv_report(int sk_rcv, int flags, struct report *r)
{
	int pidfd, ec;

	if (zdtm_recv_pidfd(sk_rcv, flags, &pidfd))
		return -1;

	if (pidfd < 0) {
		pr_err("no pidfd in cmsg: %d\n", pidfd);
		return -1;
	}

	if (zdtm_pidfs_ino(pidfd, &r->ino)) {
		close(pidfd);
		return -1;
	}

	if (zdtm_pidfd_query_exit(pidfd, &ec) == 1) {
		r->have_exit = 1;
		r->exit_code = ec;
	}

	close(pidfd);
	return 0;
}

/*
 * Establish what this kernel does, on a throwaway socketpair, before the dump
 * decides anything. Only kernels >= 6.17 mint a pidfd for a sender that has
 * already been reaped; without one there is no identity to observe and nothing
 * for this test to check.
 *
 * Returns 1 if the test can run, 0 if it must be skipped, -1 on error.
 */
static int probe_kernel(void)
{
	int sk1[2], sk2[2], snd[2], pidfd;
	struct report r1 = {}, r2 = {};
	int opt = 1, ret = -1;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sk1) < 0)
		return pr_perror("socketpair");

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sk2) < 0) {
		pr_perror("socketpair");
		close(sk1[0]);
		close(sk1[1]);
		return -1;
	}

	if (setsockopt(sk1[1], SOL_SOCKET, SO_PASSPIDFD, &opt, sizeof(opt)) < 0 ||
	    setsockopt(sk2[1], SOL_SOCKET, SO_PASSPIDFD, &opt, sizeof(opt)) < 0) {
		pr_perror("setsockopt SO_PASSPIDFD");
		goto out;
	}

	snd[0] = sk1[0];
	snd[1] = sk2[0];
	if (zdtm_queue_msg_from_dead_child(snd, 2, 42, 0, NULL) < 0)
		goto out;

	/* Peek first: a kernel that can't mint the pidfd is a skip, not a failure. */
	if (zdtm_recv_pidfd(sk1[1], MSG_PEEK, &pidfd))
		goto out;

	if (pidfd < 0) {
		test_msg("kernel can't mint pidfds of reaped senders (%d), skipping\n", pidfd);
		ret = 0;
		goto out;
	}
	close(pidfd);

	if (recv_report(sk1[1], 0, &r1) || recv_report(sk2[1], 0, &r2))
		goto out;

	/*
	 * The ground truth this test is built on. If the kernel does not hold
	 * to it there is no point checking that C/R preserves it.
	 */
	if (r1.ino != r2.ino) {
		pr_err("kernel: one sender, two packets, two inos: %llu vs %llu\n",
		       (unsigned long long)r1.ino, (unsigned long long)r2.ino);
		goto out;
	}

	ret = 1;
out:
	close(sk1[0]);
	close(sk1[1]);
	close(sk2[0]);
	close(sk2[1]);
	return ret;
}

/*
 * Run in a task of its own, owning both ends of one socketpair and nothing
 * else. It reports the identity of its packet's sender twice: once now, and
 * once after C/R. The main process compares the two tasks' answers.
 */
static int task_main(int sk_snd, int sk_rcv, int report_fd)
{
	struct report r = {};

	if (!recv_report(sk_rcv, MSG_PEEK, &r))
		r.ok = 1;

	if (write(report_fd, &r, sizeof(r)) != sizeof(r))
		return pr_perror("write");

	if (!r.ok)
		return 1;

	test_waitsig();

	memset(&r, 0, sizeof(r));
	if (!recv_report(sk_rcv, 0, &r))
		r.ok = 1;

	if (write(report_fd, &r, sizeof(r)) != sizeof(r))
		return pr_perror("write");

	close(sk_snd);
	close(sk_rcv);
	close(report_fd);
	return r.ok ? 0 : 1;
}

/*
 * Reap both tasks, and report whether either of them failed. Returns 0 when
 * both exited cleanly.
 */
static int wait_tasks(pid_t task_a, pid_t task_b)
{
	int status, ret = 0;

	if (waitpid(task_a, &status, 0) != task_a || !WIFEXITED(status) || WEXITSTATUS(status))
		ret = 1;
	if (waitpid(task_b, &status, 0) != task_b || !WIFEXITED(status) || WEXITSTATUS(status))
		ret = 1;

	return ret;
}

int main(int argc, char *argv[])
{
	struct report a = {}, b = {};
	int sk1[2], sk2[2], snd[2], rep[2];
	pid_t task_a, task_b;
	int opt = 1, ready;
	int ret = 1;

	test_init(argc, argv);

	if (zdtm_has_pidfs() != 1) {
		test_daemon();
		test_waitsig();
		skip("Test requires pidfs, skipping...");
		pass();
		return 0;
	}

	ready = probe_kernel();
	if (ready < 0)
		return 1;
	if (ready == 0) {
		test_daemon();
		test_waitsig();
		skip("Test requires a kernel that mints pidfds of reaped senders, skipping...");
		pass();
		return 0;
	}

	if (pipe(rep) < 0)
		return pr_perror("pipe");

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sk1) < 0)
		return pr_perror("socketpair");

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sk2) < 0)
		return pr_perror("socketpair");

	if (setsockopt(sk1[1], SOL_SOCKET, SO_PASSPIDFD, &opt, sizeof(opt)) < 0 ||
	    setsockopt(sk2[1], SOL_SOCKET, SO_PASSPIDFD, &opt, sizeof(opt)) < 0)
		return pr_perror("setsockopt SO_PASSPIDFD");

	/* One sender, one packet into each socket, then gone. */
	snd[0] = sk1[0];
	snd[1] = sk2[0];
	if (zdtm_queue_msg_from_dead_child(snd, 2, 42, 0, NULL) < 0)
		return 1;

	/*
	 * Hand each socketpair to a task of its own. Every fd below is closed
	 * everywhere but in the one task that is meant to own it, so that on
	 * restore criu has no choice about which process refills which queue.
	 */
	task_a = test_fork();
	if (task_a < 0)
		return pr_perror("fork");
	if (task_a == 0) {
		close(rep[0]);
		close(sk2[0]);
		close(sk2[1]);
		return task_main(sk1[0], sk1[1], rep[1]);
	}

	task_b = test_fork();
	if (task_b < 0) {
		pr_perror("fork");
		goto out_kill_a;
	}
	if (task_b == 0) {
		close(rep[0]);
		close(sk1[0]);
		close(sk1[1]);
		return task_main(sk2[0], sk2[1], rep[1]);
	}

	close(rep[1]);
	close(sk1[0]);
	close(sk1[1]);
	close(sk2[0]);
	close(sk2[1]);

	if (read(rep[0], &a, sizeof(a)) != sizeof(a) ||
	    read(rep[0], &b, sizeof(b)) != sizeof(b)) {
		pr_perror("read");
		goto out_kill;
	}

	if (!a.ok || !b.ok) {
		pr_err("a task could not read its packet before the dump\n");
		goto out_kill;
	}

	if (a.ino != b.ino) {
		pr_err("before dump: one sender, two packets, two inos: %llu vs %llu\n",
		       (unsigned long long)a.ino, (unsigned long long)b.ino);
		goto out_kill;
	}

	test_daemon();
	test_waitsig();

	kill(task_a, SIGTERM);
	kill(task_b, SIGTERM);

	if (read(rep[0], &a, sizeof(a)) != sizeof(a) ||
	    read(rep[0], &b, sizeof(b)) != sizeof(b)) {
		fail("can't read back what the restored tasks saw");
		goto out_kill;
	}

	if (!a.ok || !b.ok) {
		fail("a restored task could not get the pidfd of its packet");
		goto out_wait;
	}

	/*
	 * One process sent both packets, so both receivers must still see one
	 * process. Two inos here mean restore stood in for that one sender
	 * twice, once per task.
	 */
	if (a.ino != b.ino) {
		fail("after restore: one sender, two packets, two inos: %llu vs %llu",
		     (unsigned long long)a.ino, (unsigned long long)b.ino);
		goto out_wait;
	}

	if (a.have_exit && b.have_exit) {
		if (!WIFEXITED(a.exit_code) || WEXITSTATUS(a.exit_code) != 42 ||
		    !WIFEXITED(b.exit_code) || WEXITSTATUS(b.exit_code) != 42) {
			fail("restored senders report exit status %d and %d, expected exit 42",
			     a.exit_code, b.exit_code);
			goto out_wait;
		}
	}

	/*
	 * The verdict is only good once both tasks have been accounted for,
	 * so reap them before saying anything.
	 */
	if (wait_tasks(task_a, task_b))
		goto out;

	ret = 0;
	pass();
	close(rep[0]);
	return ret;

out_wait:
	wait_tasks(task_a, task_b);
out:
	close(rep[0]);
	return ret;

out_kill:
	kill(task_b, SIGKILL);
	waitpid(task_b, NULL, 0);
out_kill_a:
	kill(task_a, SIGKILL);
	waitpid(task_a, NULL, 0);
	close(rep[0]);
	return 1;
}
