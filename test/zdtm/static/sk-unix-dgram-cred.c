#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "zdtmtst.h"

const char *test_doc = "Test SCM_CREDENTIALS checkpoint/restore in unix socket queue\n";
const char *test_author = "Ahmed Elaidy <elaidya225@gmail.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char *argv[])
{
	int sk[2];
	struct msghdr msg = {};
	struct iovec iov;
	char buf[64];
	char cmsg_buf[CMSG_SPACE(sizeof(struct ucred))];
	struct cmsghdr *cmsg;
	struct ucred *cred;
	struct ucred send_cred;
	int opt = 1;

	test_init(argc, argv);

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sk) < 0)
		return pr_perror("socketpair");

	if (setsockopt(sk[1], SOL_SOCKET, SO_PASSCRED, &opt, sizeof(opt)) < 0)
		return pr_perror("setsockopt SO_PASSCRED");

	/* Send a message with SCM_CREDENTIALS */
	send_cred.pid = getpid();
	send_cred.uid = getuid();
	send_cred.gid = getgid();

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	memset(cmsg_buf, 0, sizeof(cmsg_buf));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf;
	msg.msg_controllen = sizeof(cmsg_buf);

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

	/* Receive and verify credentials after restore */
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

	if (cmsg->cmsg_type != SCM_CREDENTIALS) {
		fail("wrong cmsg type after restore");
		return 1;
	}

	cred = (struct ucred *)CMSG_DATA(cmsg);

	if (cred->uid != send_cred.uid || cred->gid != send_cred.gid) {
		fail("credentials mismatch after restore: "
		     "uid %d/%d gid %d/%d",
		     cred->uid, send_cred.uid,
		     cred->gid, send_cred.gid);
		return 1;
	}

	close(sk[0]);
	close(sk[1]);

	pass();
	return 0;
}