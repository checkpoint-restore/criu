#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <limits.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc = "Test unix stream sockets with ucreds in queue\n";
const char *test_author = "Cyrill Gorcunov <gorcunov@openvz.org";

char *filename;
TEST_OPTION(filename, string, "socket file name", 1);

int main(int argc, char *argv[])
{
	struct sockaddr_un addr;
	unsigned int addrlen;
	int sock[2], accepted;

	int ret, data;
	char path[PATH_MAX];
	char *cwd;

	struct ucred *ucredp, ucred, *ucp;
	struct msghdr msgh;
	struct iovec iov;
	ssize_t nr;

	union {
		struct cmsghdr cmh;
		char control[CMSG_SPACE(sizeof(struct ucred))];
	} control_un;
	struct cmsghdr *cmhp;
	socklen_t len;

	test_init(argc, argv);

	cwd = get_current_dir_name();
	if (!cwd) {
		pr_perror("getcwd");
		exit(1);
	}

	snprintf(path, sizeof(path), "%s/%s", cwd, filename);
	unlink(path);

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, filename, sizeof(addr.sun_path) - 1);
	addrlen = sizeof(addr.sun_family) + strlen(filename);

	sock[0] = socket(AF_UNIX, SOCK_STREAM, 0);
	sock[1] = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock[0] < 0 || sock[1] < 0) {
		pr_perror("socket");
		exit(1);
	}

	if (setsockopt(sock[0], SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0 ||
	    setsockopt(sock[1], SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0) {
		pr_perror("setsockopt SO_REUSEADDR");
		exit(1);
	}

	if (setsockopt(sock[0], SOL_SOCKET, SO_PASSCRED, &(int){ 1 }, sizeof(int)) < 0 ||
	    setsockopt(sock[1], SOL_SOCKET, SO_PASSCRED, &(int){ 1 }, sizeof(int)) < 0) {
		pr_perror("setsockopt SO_PASSCRED");
		exit(1);
	}

	ret = bind(sock[0], (struct sockaddr *)&addr, addrlen);
	if (ret) {
		pr_perror("bind");
		exit(1);
	}

	ret = listen(sock[0], 16);
	if (ret) {
		pr_perror("bind");
		exit(1);
	}

	if (connect(sock[1], (struct sockaddr *)&addr, addrlen)) {
		pr_perror("connect");
		exit(1);
	}

	accepted = accept(sock[0], NULL, NULL);
	if (accepted < 0) {
		pr_perror("accept");
		exit(1);
	}

	control_un.cmh.cmsg_len = CMSG_LEN(sizeof(struct ucred));
	control_un.cmh.cmsg_level = SOL_SOCKET;
	control_un.cmh.cmsg_type = SCM_CREDENTIALS;

	msgh.msg_control = control_un.control;
	msgh.msg_controllen = sizeof(control_un.control);

	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	iov.iov_base = &data;
	iov.iov_len = sizeof(data);

	msgh.msg_name = NULL;
	msgh.msg_namelen = 0;

	cmhp = CMSG_FIRSTHDR(&msgh);
	cmhp->cmsg_len = CMSG_LEN(sizeof(struct ucred));
	cmhp->cmsg_level = SOL_SOCKET;
	cmhp->cmsg_type = SCM_CREDENTIALS;
	ucp = (struct ucred *)CMSG_DATA(cmhp);
	ucp->pid = getpid();
	ucp->uid = getuid();
	ucp->gid = getgid();

	if (sendmsg(sock[1], &msgh, 0) < 0) {
		pr_perror("send");
		exit(1);
	}

	test_daemon();
	test_waitsig();

	control_un.cmh.cmsg_len = CMSG_LEN(sizeof(struct ucred));
	control_un.cmh.cmsg_level = SOL_SOCKET;
	control_un.cmh.cmsg_type = SCM_CREDENTIALS;

	msgh.msg_control = control_un.control;
	msgh.msg_controllen = sizeof(control_un.control);

	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	iov.iov_base = &data;
	iov.iov_len = sizeof(data);

	msgh.msg_name = NULL;
	msgh.msg_namelen = 0;

	nr = recvmsg(accepted, &msgh, 0);
	if (nr < 0) {
		fail("recvmsg");
		exit(1);
	}

	cmhp = CMSG_FIRSTHDR(&msgh);
	if (cmhp == NULL || cmhp->cmsg_len != CMSG_LEN(sizeof(struct ucred))) {
		fail("bad cmsg header / message length");
		exit(1);
	}

	if (cmhp->cmsg_level != SOL_SOCKET) {
		fail("cmsg_level != SOL_SOCKET");
		exit(1);
	}

	if (cmhp->cmsg_type != SCM_CREDENTIALS) {
		pr_err("cmsg_type != SCM_CREDENTIALS\n");
		exit(1);
	}

	ucredp = (struct ucred *)CMSG_DATA(cmhp);
	test_msg("Received credentials pid=%ld, uid=%ld, gid=%ld\n",
		 (long) ucredp->pid, (long) ucredp->uid, (long) ucredp->gid);

	len = sizeof(struct ucred);
	if (getsockopt(sock[0], SOL_SOCKET, SO_PEERCRED, &ucred, &len) == -1) {
		fail("getsockopt");
		exit(1);
	}

	test_msg("Credentials from SO_PEERCRED: pid=%ld, euid=%ld, egid=%ld\n",
		 (long) ucred.pid, (long) ucred.uid, (long) ucred.gid);

	pass();
	return 0;
}
