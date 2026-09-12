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

#ifndef SO_PASSPIDFD
#define SO_PASSPIDFD 76
#endif

#ifndef SCM_PIDFD
#define SCM_PIDFD 0x04
#endif

#ifndef PID_FS_MAGIC
#define PID_FS_MAGIC 0x50494446
#endif

/*
 * PIDFD_GET_INFO (pidfs ioctl, Linux 6.13) reports the exit status pidfs kept
 * for a process that has already been reaped. The struct layout is versioned
 * by size and encoded in the ioctl number, so use our own copy of the first
 * published 64-byte version -- exit_code is its last field -- rather than
 * whatever <linux/pidfd.h> the build host happens to have.
 */
struct zdtm_pidfd_info {
	uint64_t mask;
	uint64_t cgroupid;
	uint32_t pid;
	uint32_t tgid;
	uint32_t ppid;
	uint32_t ruid;
	uint32_t rgid;
	uint32_t euid;
	uint32_t egid;
	uint32_t suid;
	uint32_t sgid;
	uint32_t fsuid;
	uint32_t fsgid;
	int32_t exit_code;
};

#define ZDTM_PIDFD_INFO_EXIT (1UL << 3)
#define ZDTM_PIDFD_GET_INFO  _IOWR(0xFF, 11, struct zdtm_pidfd_info)

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

static int pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

static int has_pidfs(void)
{
	struct statfs fst;
	int pidfd, ret;

	pidfd = pidfd_open(getpid(), 0);
	if (pidfd < 0) {
		pr_perror("pidfd_open");
		return -1;
	}

	ret = fstatfs(pidfd, &fst);
	close(pidfd);
	if (ret < 0) {
		pr_perror("fstatfs");
		return -1;
	}

	return fst.f_type == PID_FS_MAGIC;
}

/* The pidfs inode number, which uniquely identifies the struct pid. */
static int pidfs_ino(int pidfd, uint64_t *ino)
{
	struct statx stx;

	if (statx(pidfd, "", AT_EMPTY_PATH, STATX_INO, &stx) < 0)
		return pr_perror("statx");

	*ino = stx.stx_ino;
	return 0;
}

/*
 * Read the exit status of the process a pidfd refers to. Returns 1 and fills
 * *exit_code (a wait(2)-style status word) if the task exited, 0 if it is
 * alive, and -1 if PIDFD_GET_INFO / PIDFD_INFO_EXIT is unavailable.
 */
static int pidfd_query_exit(int pidfd, int *exit_code)
{
	struct zdtm_pidfd_info info = { .mask = ZDTM_PIDFD_INFO_EXIT };

	if (ioctl(pidfd, ZDTM_PIDFD_GET_INFO, &info) < 0)
		return -1;
	if (!(info.mask & ZDTM_PIDFD_INFO_EXIT))
		return 0;
	*exit_code = info.exit_code;
	return 1;
}

/* Pull the SCM_PIDFD payload out of the next packet on @sk_rcv. */
static int recv_pidfd(int sk_rcv, int flags, int *pidfd)
{
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	struct iovec iov;
	char buf[64];
	char cmsg_buf[CMSG_SPACE(sizeof(int))];

	memset(buf, 0, sizeof(buf));
	memset(cmsg_buf, 0, sizeof(cmsg_buf));
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf;
	msg.msg_controllen = sizeof(cmsg_buf);

	if (recvmsg(sk_rcv, &msg, flags) < 0)
		return pr_perror("recvmsg");

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg) {
		pr_err("no cmsg\n");
		return -1;
	}

	if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_PIDFD) {
		pr_err("wrong cmsg: level %d type %d\n",
		       cmsg->cmsg_level, cmsg->cmsg_type);
		return -1;
	}

	memcpy(pidfd, CMSG_DATA(cmsg), sizeof(*pidfd));
	return 0;
}

/* As recv_pidfd(), but also demand a usable pidfd and fill in the report. */
static int recv_report(int sk_rcv, int flags, struct report *r)
{
	int pidfd, ec;

	if (recv_pidfd(sk_rcv, flags, &pidfd))
		return -1;

	if (pidfd < 0) {
		pr_err("no pidfd in cmsg: %d\n", pidfd);
		return -1;
	}

	if (pidfs_ino(pidfd, &r->ino)) {
		close(pidfd);
		return -1;
	}

	if (pidfd_query_exit(pidfd, &ec) == 1) {
		r->have_exit = 1;
		r->exit_code = ec;
	}

	close(pidfd);
	return 0;
}

/*
 * Queue one datagram into each of @sk_a and @sk_b from a child that exits with
 * @exit_code and is reaped before we return. Both packets then carry the very
 * same struct pid, of a process that no longer exists.
 */
static int queue_msg_from_dead_child(int sk_a, int sk_b, int exit_code)
{
	int status;
	pid_t child;

	child = fork();
	if (child < 0)
		return pr_perror("fork");

	if (child == 0) {
		char buf[] = "hello";
		struct iovec iov = {
			.iov_base = buf,
			.iov_len = sizeof(buf),
		};
		struct msghdr msg = {
			.msg_iov = &iov,
			.msg_iovlen = 1,
		};

		if (sendmsg(sk_a, &msg, 0) < 0)
			_exit(255);
		if (sendmsg(sk_b, &msg, 0) < 0)
			_exit(255);
		_exit(exit_code);
	}

	if (waitpid(child, &status, 0) != child)
		return pr_perror("waitpid");

	if (!WIFEXITED(status) || WEXITSTATUS(status) != exit_code) {
		pr_err("child failed to send or exit with %d\n", exit_code);
		return -1;
	}

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
	int sk1[2], sk2[2], pidfd;
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

	if (queue_msg_from_dead_child(sk1[0], sk2[0], 42))
		goto out;

	/* Peek first: a kernel that can't mint the pidfd is a skip, not a failure. */
	if (recv_pidfd(sk1[1], MSG_PEEK, &pidfd))
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

int main(int argc, char *argv[])
{
	struct report a = {}, b = {};
	int sk1[2], sk2[2], rep[2];
	pid_t task_a, task_b;
	int opt = 1, ready;
	int status, ret = 1;

	test_init(argc, argv);

	if (has_pidfs() != 1) {
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
	if (queue_msg_from_dead_child(sk1[0], sk2[0], 42))
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

	ret = 0;
	pass();

out_wait:
	if (waitpid(task_a, &status, 0) == task_a && (!WIFEXITED(status) || WEXITSTATUS(status)))
		ret = 1;
	if (waitpid(task_b, &status, 0) == task_b && (!WIFEXITED(status) || WEXITSTATUS(status)))
		ret = 1;
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
