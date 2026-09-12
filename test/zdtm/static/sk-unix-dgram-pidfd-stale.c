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

#include <stdint.h>
#include <sys/ioctl.h>

#ifndef SO_PASSPIDFD
#define SO_PASSPIDFD 76
#endif

#ifndef SCM_PIDFD
#define SCM_PIDFD 0x04
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

const char *test_doc = "Test C/R of a stale pidfd in unix socket queue (sender died before dump)\n";
const char *test_author = "Ahmed Elaidy <elaidya225@gmail.com>";

static int pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags)
{
	return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
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

/* Returns the fdinfo Pid field (-1 for a dead process), or -2 on error */
static pid_t pidfd_get_pid(int pidfd)
{
	char path[64];
	char line[256];
	pid_t pid = -2;
	FILE *f;

	snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", pidfd);
	f = fopen(path, "r");
	if (!f) {
		pr_perror("fopen %s", path);
		return -2;
	}

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "Pid: %d", &pid) == 1)
			break;
	}

	fclose(f);
	return pid;
}

/*
 * Queue one message into sk_snd from a child which then terminates and is
 * reaped before we return, so the skb pid points to a dead process. The child
 * dies either with exit code @exit_code (when @term_sig is 0) or by raising
 * @term_sig, so we can check C/R preserves the sender's exit status.
 */
static int queue_msg_from_dead_child(int sk_snd, int exit_code, int term_sig)
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

		if (sendmsg(sk_snd, &msg, 0) < 0)
			_exit(255);
		if (term_sig) {
			sigset_t unblock;

			/* Ensure the signal is deliverable, then die from it. */
			sigemptyset(&unblock);
			sigaddset(&unblock, term_sig);
			sigprocmask(SIG_UNBLOCK, &unblock, NULL);
			signal(term_sig, SIG_DFL);
			raise(term_sig);
		}
		_exit(exit_code);
	}

	if (waitpid(child, &status, 0) != child)
		return pr_perror("waitpid");

	if (term_sig) {
		if (!WIFSIGNALED(status) || WTERMSIG(status) != term_sig) {
			pr_err("child not killed by signal %d\n", term_sig);
			return -1;
		}
	} else {
		if (!WIFEXITED(status) || WEXITSTATUS(status) != exit_code) {
			pr_err("child failed to send or exit with %d\n", exit_code);
			return -1;
		}
	}

	return 0;
}

static int recv_pidfd(int sk_rcv, int *pidfd)
{
	struct msghdr msg = {};
	struct iovec iov;
	char buf[64];
	char cmsg_buf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;

	memset(buf, 0, sizeof(buf));
	memset(cmsg_buf, 0, sizeof(cmsg_buf));
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf;
	msg.msg_controllen = sizeof(cmsg_buf);

	if (recvmsg(sk_rcv, &msg, 0) < 0)
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
	if (queue_msg_from_dead_child(sk[0], 123, 0))
		goto err;

	if (recv_pidfd(sk[1], &pidfd))
		goto err;

	close(sk[0]);
	close(sk[1]);

	if (pidfd < 0)
		return 0;

	if (pidfd_query_exit(pidfd, &ec) == 1 && WIFEXITED(ec) && WEXITSTATUS(ec) == 123)
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

	if (recv_pidfd(sk_rcv, &pidfd)) {
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
	if (pidfd_send_signal(pidfd, 0, NULL, 0) == 0 || errno != ESRCH) {
		close(pidfd);
		fail("pidfd is not stale after restore");
		return -1;
	}

	if (pidfd_get_pid(pidfd) != -1) {
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
		if (pidfd_query_exit(pidfd, &ec) != 1)
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
	 * exited with a code, one was killed by a signal -- which exercises
	 * restore's per-exit-status helper grouping. The third died exactly
	 * like the first, so restore stands in for both with a single helper
	 * and must still report the right status for each packet.
	 */
	if (queue_msg_from_dead_child(sk[0], 42, 0))
		return 1;
	if (queue_msg_from_dead_child(sk[0], 0, SIGUSR1))
		return 1;
	if (queue_msg_from_dead_child(sk[0], 42, 0))
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
