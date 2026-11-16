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
#include "zdtm_pidfd.h"

const char *test_doc = "Test SCM_CREDENTIALS + SCM_PIDFD checkpoint/restore in one unix socket queue\n";
const char *test_author = "Ahmed Elaidy <elaidya225@gmail.com>";

int main(int argc, char *argv[])
{
	int sk[2];
	struct msghdr msg = {};
	struct iovec iov;
	char buf[64];
	char cmsg_buf[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	struct ucred send_cred;
	struct ucred *cred = NULL;
	int opt = 1;
	int pidfd = -1;
	pid_t pid;

	test_init(argc, argv);

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sk) < 0)
		return pr_perror("socketpair");

	if (setsockopt(sk[1], SOL_SOCKET, SO_PASSCRED, &opt, sizeof(opt)) < 0)
		return pr_perror("setsockopt SO_PASSCRED");

	if (setsockopt(sk[1], SOL_SOCKET, SO_PASSPIDFD, &opt, sizeof(opt)) < 0)
		return pr_perror("setsockopt SO_PASSPIDFD");

	/* Send a message with explicit SCM_CREDENTIALS */
	send_cred.pid = getpid();
	send_cred.uid = getuid();
	send_cred.gid = getgid();

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	memset(cmsg_buf, 0, sizeof(cmsg_buf));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf;
	msg.msg_controllen = CMSG_SPACE(sizeof(struct ucred));

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_CREDENTIALS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
	memcpy(CMSG_DATA(cmsg), &send_cred, sizeof(struct ucred));

	strcpy(buf, "hello");
	if (sendmsg(sk[0], &msg, 0) < 0)
		return pr_perror("sendmsg");

	test_daemon();
	test_waitsig();

	/* Both cmsgs must arrive in one recvmsg after restore */
	memset(buf, 0, sizeof(buf));
	memset(cmsg_buf, 0, sizeof(cmsg_buf));
	msg.msg_control = cmsg_buf;
	msg.msg_controllen = sizeof(cmsg_buf);
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	if (recvmsg(sk[1], &msg, 0) < 0)
		return pr_perror("recvmsg");

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != SOL_SOCKET)
			continue;
		if (cmsg->cmsg_type == SCM_CREDENTIALS)
			cred = (struct ucred *)CMSG_DATA(cmsg);
		else if (cmsg->cmsg_type == SCM_PIDFD)
			memcpy(&pidfd, CMSG_DATA(cmsg), sizeof(pidfd));
	}

	if (!cred) {
		fail("no SCM_CREDENTIALS after restore");
		return 1;
	}

	if (pidfd < 0) {
		fail("no SCM_PIDFD after restore");
		return 1;
	}

	if (cred->uid != send_cred.uid || cred->gid != send_cred.gid) {
		fail("credentials mismatch after restore: "
		     "uid %d/%d gid %d/%d",
		     cred->uid, send_cred.uid,
		     cred->gid, send_cred.gid);
		return 1;
	}

	if (zdtm_pidfd_send_signal(pidfd, 0, NULL, 0))
		return pr_perror("zdtm_pidfd_send_signal");

	/* The pidfd and the creds are two views of the same skb pid */
	pid = zdtm_pidfd_get_pid(pidfd);
	if (pid != cred->pid || pid != getpid()) {
		fail("pid mismatch after restore: pidfd %d cred %d self %d",
		     pid, cred->pid, getpid());
		return 1;
	}

	close(pidfd);
	close(sk[0]);
	close(sk[1]);

	pass();
	return 0;
}
