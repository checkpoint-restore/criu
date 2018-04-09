#include <unistd.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <linux/socket.h>
#include <string.h>

#include "zdtmtst.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK     270
#endif

#define	UDEV_MONITOR_TEST 32

const char *test_doc	= "Support of netlink sockets";
const char *test_author	= "Andrew Vagin <avagin@parallels.com>";

int main(int argc, char ** argv)
{
	int ssk, bsk, csk, dsk;
	struct sockaddr_nl addr;
	struct msghdr msg;
	struct {
		struct nlmsghdr hdr;
	} req;
	struct iovec iov;
	char buf[4096];

	test_init(argc, argv);

	ssk = socket(PF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
	if (ssk < 0) {
		pr_perror("Can't create sock diag socket");
		return -1;
	}
	bsk = socket(PF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
	if (bsk < 0) {
		pr_perror("Can't create sock diag socket");
		return -1;
	}
#if 0
	int on, bbsk;

	bbsk = socket(PF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
	if (bbsk < 0) {
		pr_perror("Can't create sock diag socket");
		return -1;
	}

	on = UDEV_MONITOR_TEST;
	setsockopt(bbsk, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &on, sizeof(on));
#endif
	csk = socket(PF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
	if (csk < 0) {
		pr_perror("Can't create sock diag socket");
		return -1;
	}
	dsk = socket(PF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
	if (dsk < 0) {
		pr_perror("Can't create sock diag socket");
		return -1;
	}

	addr.nl_family = AF_NETLINK;
	addr.nl_groups = 0;
	addr.nl_pid = getpid();
	if (bind(ssk, (struct sockaddr *) &addr, sizeof(struct sockaddr_nl))) {
		pr_perror("bind");
		return 1;
	}

	addr.nl_groups = 1 << (UDEV_MONITOR_TEST - 1);
	addr.nl_pid = 0;
	if (bind(bsk, (struct sockaddr *) &addr, sizeof(struct sockaddr_nl))) {
		pr_perror("bind");
		return 1;
	}

	addr.nl_pid = getpid();
	addr.nl_groups = 1 << (UDEV_MONITOR_TEST - 1);
	if (connect(csk, (struct sockaddr *) &addr, sizeof(struct sockaddr_nl))) {
		pr_perror("connect");
		return 1;
	}

	test_daemon();

	test_waitsig();

	req.hdr.nlmsg_len       = sizeof(req);
	req.hdr.nlmsg_type      = 0x1234;
	req.hdr.nlmsg_flags     = NLM_F_DUMP | NLM_F_REQUEST;
	req.hdr.nlmsg_seq       = 0xabcd;

	memset(&msg, 0, sizeof(msg));
	msg.msg_namelen = 0;
	msg.msg_iov     = &iov;
	msg.msg_iovlen  = 1;

	iov.iov_base    = (void *) &req;
	iov.iov_len     = sizeof(req);

	if (sendmsg(csk, &msg, 0) < 0) {
		pr_perror("Can't send request message");
		return 1;
	}

	memset(&msg, 0, sizeof(msg));
	msg.msg_namelen = 0;
	msg.msg_iov     = &iov;
	msg.msg_iovlen  = 1;

	iov.iov_base    = buf;
	iov.iov_len     = sizeof(buf);

	if (recvmsg(ssk, &msg, 0) < 0) {
		pr_perror("Can't recv request message");
		return 1;
	}

	if (recvmsg(bsk, &msg, 0) < 0) {
		pr_perror("Can't recv request message");
		return 1;
	}

	addr.nl_family = AF_NETLINK;
	addr.nl_groups = 0;
	addr.nl_pid = getpid();

	memset(&msg, 0, sizeof(msg));
	msg.msg_namelen = sizeof(addr);
	msg.msg_name	= &addr;
	msg.msg_iov     = &iov;
	msg.msg_iovlen  = 1;

	iov.iov_base    = (void *) &req;
	iov.iov_len     = sizeof(req);

	if (sendmsg(dsk, &msg, 0) < 0) {
		pr_perror("Can't send request message");
		return 1;
	}

	memset(&msg, 0, sizeof(msg));
	msg.msg_namelen = 0;
	msg.msg_iov     = &iov;
	msg.msg_iovlen  = 1;

	iov.iov_base    = buf;
	iov.iov_len     = sizeof(buf);

	if (recvmsg(ssk, &msg, 0) < 0) {
		pr_perror("Can't recv request message");
		return 1;
	}

	pass();

	return 0;
}
