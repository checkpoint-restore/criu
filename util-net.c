#include <sys/socket.h>
#include <sys/un.h>

#include "syscall.h"

int send_fd(int sock, struct sockaddr_un *saddr, int len, int fd)
{
	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	struct msghdr hdr = { };
	struct iovec data = { };
	struct cmsghdr* cmsg;
	int *cmsg_data;
	char dummy = '*';

	data.iov_base	= &dummy;
	data.iov_len	= sizeof(dummy);

	hdr.msg_name	= (struct sockaddr *)saddr;
	hdr.msg_namelen	= len;
	hdr.msg_iov	= &data;
	hdr.msg_iovlen	= 1;

	hdr.msg_control = &cmsgbuf;
	hdr.msg_controllen = CMSG_LEN(sizeof(int));

	cmsg = CMSG_FIRSTHDR(&hdr);
	cmsg->cmsg_len   = hdr.msg_controllen;
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type  = SCM_RIGHTS;

	cmsg_data = (int *)CMSG_DATA(cmsg);
	*cmsg_data = fd;

	return sys_sendmsg(sock, &hdr, 0);
}

int recv_fd(int sock)
{
	char ccmsg[CMSG_SPACE(sizeof(int))];
	struct msghdr msg = { };
	struct iovec iov = { };
	struct cmsghdr *cmsg;
	int *cmsg_data;
	char buf[1];
	int ret;

	iov.iov_base	= buf;
	iov.iov_len	= 1;

	msg.msg_iov	= &iov;
	msg.msg_iovlen	= 1;
	msg.msg_control	= ccmsg;
	msg.msg_controllen = sizeof(ccmsg);

	ret = sys_recvmsg(sock, &msg, 0);
	if (ret < 0)
		return ret;

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg || !cmsg->cmsg_type == SCM_RIGHTS)
		return -2;

	cmsg_data = (int *)CMSG_DATA(cmsg);
	return *cmsg_data;
}

