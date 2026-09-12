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

/*
 * Queue one datagram into @sk_snd from a child that exits with @exit_code and
 * is reaped before we return, so the skb pid points to a dead process. When
 * @pidfd is not NULL, a pidfd of the child is opened while it is still alive
 * and handed back: the caller then holds a pidfd of the very process whose skb
 * is now sitting in the queue.
 */
static int queue_msg_from_dead_child(int sk_snd, int exit_code, int *pidfd)
{
	int p[2], status, fd = -1;
	pid_t child;
	char go = 1;

	if (pipe(p) < 0)
		return pr_perror("pipe");

	child = fork();
	if (child < 0) {
		close(p[0]);
		close(p[1]);
		return pr_perror("fork");
	}

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

		close(p[1]);
		/* Stay alive until the parent has had a chance to pidfd_open() us. */
		if (read(p[0], &go, sizeof(go)) != sizeof(go))
			_exit(255);
		if (sendmsg(sk_snd, &msg, 0) < 0)
			_exit(255);
		_exit(exit_code);
	}

	close(p[0]);

	if (pidfd) {
		fd = pidfd_open(child, 0);
		if (fd < 0) {
			pr_perror("pidfd_open");
			goto err;
		}
	}

	if (write(p[1], &go, sizeof(go)) != sizeof(go)) {
		pr_perror("write");
		goto err;
	}
	close(p[1]);

	if (waitpid(child, &status, 0) != child) {
		pr_perror("waitpid");
		goto err_reaped;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != exit_code) {
		pr_err("child failed to send or exit with %d\n", exit_code);
		goto err_reaped;
	}

	if (pidfd)
		*pidfd = fd;
	return 0;

err:
	close(p[1]);
	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
err_reaped:
	if (fd >= 0)
		close(fd);
	return -1;
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

/* As recv_pidfd(), but also demand a usable pidfd and return its pidfs ino. */
static int recv_pidfd_ino(int sk_rcv, int flags, uint64_t *ino, int *exit_code)
{
	int pidfd, ret;

	if (recv_pidfd(sk_rcv, flags, &pidfd))
		return -1;

	if (pidfd < 0) {
		pr_err("no pidfd in cmsg: %d\n", pidfd);
		return -1;
	}

	ret = pidfs_ino(pidfd, ino);
	if (!ret && exit_code && pidfd_query_exit(pidfd, exit_code) != 1) {
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

	if (queue_msg_from_dead_child(sk[0], 42, &held))
		goto err;
	if (queue_msg_from_dead_child(sk[0], 42, NULL))
		goto err;

	/* Peek first: a kernel that can't mint the pidfd is a skip, not a failure. */
	if (recv_pidfd(sk[1], MSG_PEEK, &pidfd))
		goto err;

	if (pidfd < 0) {
		test_msg("kernel can't mint pidfds of reaped senders (%d), skipping\n", pidfd);
		close(held);
		close(sk[0]);
		close(sk[1]);
		return 0;
	}
	close(pidfd);

	if (pidfs_ino(held, &ino_held))
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

	if (pidfd_query_exit(held, &ec) == 1 && WIFEXITED(ec) && WEXITSTATUS(ec) == 42)
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

	if (has_pidfs() != 1) {
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
	if (queue_msg_from_dead_child(sk[0], 42, &held))
		return 1;
	if (queue_msg_from_dead_child(sk[0], 42, NULL))
		return 1;
	if (queue_msg_from_dead_child(sk[0], 42, NULL))
		return 1;

	if (pidfs_ino(held, &ino_held))
		return 1;
	if (recv_pidfd(sk[1], MSG_PEEK, &peeked))
		return 1;
	if (peeked < 0) {
		pr_err("no pidfd in cmsg before dump: %d\n", peeked);
		return 1;
	}
	if (pidfs_ino(peeked, &ino_1)) {
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

	if (pidfs_ino(held, &ino_held)) {
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
