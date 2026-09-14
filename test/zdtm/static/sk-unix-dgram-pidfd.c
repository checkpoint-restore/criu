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
#include "zdtmtst.h"

#ifndef SO_PASSPIDFD
#define SO_PASSPIDFD 76
#endif

#ifndef SCM_PIDFD
#define SCM_PIDFD 0x04
#endif

const char *test_doc = "Test SCM_PIDFD checkpoint/restore in unix socket queue\n";
const char *test_author = "Ahmed Elaidy <elaidya225@gmail.com>";

static int pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags)
{
	return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
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

int main(int argc, char *argv[])
{
	int sk[2];
	struct msghdr msg = {};
	struct iovec iov;
	char buf[64];
	char cmsg_buf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	int opt = 1;
	int pidfd;
	pid_t pid;
	socklen_t len;

	test_init(argc, argv);

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sk) < 0)
		return pr_perror("socketpair");

	if (setsockopt(sk[1], SOL_SOCKET, SO_PASSPIDFD, &opt, sizeof(opt)) < 0)
		return pr_perror("setsockopt SO_PASSPIDFD");

	/*
	 * A plain sendmsg: the kernel attaches the sender pid to the
	 * queued skb because the receiver has SO_PASSPIDFD set.
	 */
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	strcpy(buf, "hello");
	if (sendmsg(sk[0], &msg, 0) < 0)
		return pr_perror("sendmsg");

	test_daemon();
	test_waitsig();

	/* Check the socket option survived */
	opt = 0;
	len = sizeof(opt);
	if (getsockopt(sk[1], SOL_SOCKET, SO_PASSPIDFD, &opt, &len) < 0)
		return pr_perror("getsockopt SO_PASSPIDFD");
	if (opt != 1) {
		fail("SO_PASSPIDFD not restored");
		return 1;
	}

	/* Receive and verify the pidfd after restore */
	memset(buf, 0, sizeof(buf));
	memset(cmsg_buf, 0, sizeof(cmsg_buf));
	msg.msg_control = cmsg_buf;
	msg.msg_controllen = sizeof(cmsg_buf);
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	if (recvmsg(sk[1], &msg, 0) < 0)
		return pr_perror("recvmsg");

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg) {
		fail("no cmsg after restore");
		return 1;
	}

	if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_PIDFD) {
		fail("wrong cmsg after restore: level %d type %d",
		     cmsg->cmsg_level, cmsg->cmsg_type);
		return 1;
	}

	memcpy(&pidfd, CMSG_DATA(cmsg), sizeof(pidfd));
	if (pidfd < 0) {
		fail("invalid pidfd %d after restore", pidfd);
		return 1;
	}

	if (pidfd_send_signal(pidfd, 0, NULL, 0))
		return pr_perror("pidfd_send_signal");

	pid = pidfd_get_pid(pidfd);
	if (pid != getpid()) {
		fail("pidfd pid mismatch after restore: %d/%d", pid, getpid());
		return 1;
	}

	close(pidfd);
	close(sk[0]);
	close(sk[1]);

	pass();
	return 0;
}
