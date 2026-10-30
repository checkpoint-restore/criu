#ifndef __ZDTM_PIDFD_H__
#define __ZDTM_PIDFD_H__

#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "zdtmtst.h"

/*
 * What several pidfd tests need from the kernel and from each other. The
 * helpers are inline so that a test including this header pays for nothing
 * it does not call.
 */

#ifndef SO_PASSPIDFD
#define SO_PASSPIDFD 76
#endif

#ifndef SCM_PIDFD
#define SCM_PIDFD 0x04
#endif

#ifndef PID_FS_MAGIC
#define PID_FS_MAGIC 0x50494446
#endif

/* Keep this layout independent of the build host's linux/pidfd.h version. */
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

/*
 * Read the exit status of the process a pidfd refers to. Returns 1 and fills
 * *exit_code (a wait(2)-style status word) if the task exited, 0 if it is
 * alive, and -1 if PIDFD_GET_INFO / PIDFD_INFO_EXIT is unavailable.
 */
static inline int zdtm_pidfd_query_exit(int pidfd, int *exit_code)
{
	struct zdtm_pidfd_info info = { .mask = ZDTM_PIDFD_INFO_EXIT };

	if (ioctl(pidfd, ZDTM_PIDFD_GET_INFO, &info) < 0)
		return -1;
	if (!(info.mask & ZDTM_PIDFD_INFO_EXIT))
		return 0;
	*exit_code = info.exit_code;
	return 1;
}

static inline int zdtm_pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

static inline int zdtm_pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags)
{
	return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
}

/* Returns the fdinfo Pid field (-1 for a dead process), or -2 on error */
static inline pid_t zdtm_pidfd_get_pid(int pidfd)
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

/* Is this a kernel with pidfs, where a pidfd has an inode of its own? */
static inline int zdtm_has_pidfs(void)
{
	struct statfs fst;
	int pidfd, ret;

	pidfd = zdtm_pidfd_open(getpid(), 0);
	if (pidfd < 0) {
		pr_perror("zdtm_pidfd_open");
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
static inline int zdtm_pidfs_ino(int pidfd, uint64_t *ino)
{
	struct statx stx;

	if (statx(pidfd, "", AT_EMPTY_PATH, STATX_INO, &stx) < 0)
		return pr_perror("statx");

	*ino = stx.stx_ino;
	return 0;
}

/* Pull the SCM_PIDFD payload out of the next packet on @sk_rcv. */
static inline int zdtm_recv_pidfd(int sk_rcv, int flags, int *pidfd)
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
		pr_err("wrong cmsg: level %d type %d\n", cmsg->cmsg_level, cmsg->cmsg_type);
		return -1;
	}

	memcpy(pidfd, CMSG_DATA(cmsg), sizeof(*pidfd));
	return 0;
}

/*
 * Queue a datagram from a child that is dead by the time we return, which is
 * what the SCM_PIDFD tests are all built on: the packet's sender is gone, so
 * the pidfd its skb refers to is stale and dump has to stand in for it.
 *
 * The child sends one datagram on each of the @nr_snd sockets in @sk_snd, then
 * dies: by raising @term_sig when that is non-zero, otherwise by exiting with
 * @exit_code. When @pidfd is given, the parent opens a pidfd of the child while
 * it is still alive and stores it there for the caller to close.
 *
 * Returns the pid the child had, now reaped, or -1 on error.
 */
static inline pid_t zdtm_queue_msg_from_dead_child(const int *sk_snd, int nr_snd, int exit_code, int term_sig,
						   int *pidfd)
{
	int p[2], status, fd = -1, i;
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
		/* Stay alive until the parent has had its chance to open a pidfd. */
		if (read(p[0], &go, sizeof(go)) != sizeof(go))
			_exit(255);

		for (i = 0; i < nr_snd; i++) {
			if (sendmsg(sk_snd[i], &msg, 0) < 0)
				_exit(255);
		}

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

	close(p[0]);

	if (pidfd) {
		fd = zdtm_pidfd_open(child, 0);
		if (fd < 0) {
			pr_perror("zdtm_pidfd_open");
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

	if (term_sig) {
		if (!WIFSIGNALED(status) || WTERMSIG(status) != term_sig) {
			pr_err("child not killed by signal %d\n", term_sig);
			goto err_reaped;
		}
	} else if (!WIFEXITED(status) || WEXITSTATUS(status) != exit_code) {
		pr_err("child failed to send or exit with %d\n", exit_code);
		goto err_reaped;
	}

	if (pidfd)
		*pidfd = fd;
	return child;

err:
	close(p[1]);
	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
err_reaped:
	if (fd >= 0)
		close(fd);
	return -1;
}

#endif /* __ZDTM_PIDFD_H__ */
