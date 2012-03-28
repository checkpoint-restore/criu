#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>

#include "compiler.h"
#include "types.h"
#include "syscall.h"

#include "util-net.h"

static void scm_fdset_init_chunk(struct scm_fdset *fdset, int nr_fds)
{
	struct cmsghdr *cmsg;

	fdset->hdr.msg_controllen = CMSG_LEN(sizeof(int) * nr_fds);

	cmsg		= CMSG_FIRSTHDR(&fdset->hdr);
	cmsg->cmsg_len	= fdset->hdr.msg_controllen;
}

static int *scm_fdset_init(struct scm_fdset *fdset, struct sockaddr_un *saddr, int saddr_len)
{
	struct cmsghdr *cmsg;

	BUILD_BUG_ON(CR_SCM_MAX_FD > SCM_MAX_FD);
	BUILD_BUG_ON(sizeof(fdset->msg_buf) < (CMSG_SPACE(sizeof(int) * CR_SCM_MAX_FD)));

	fdset->msg			= '*';

	fdset->iov.iov_base		= &fdset->msg;
	fdset->iov.iov_len		= sizeof(fdset->msg);

	fdset->hdr.msg_iov		= &fdset->iov;
	fdset->hdr.msg_iovlen		= 1;
	fdset->hdr.msg_name		= (struct sockaddr *)saddr;
	fdset->hdr.msg_namelen		= saddr_len;

	fdset->hdr.msg_control		= &fdset->msg_buf;
	fdset->hdr.msg_controllen	= CMSG_LEN(sizeof(int) * CR_SCM_MAX_FD);

	cmsg				= CMSG_FIRSTHDR(&fdset->hdr);
	cmsg->cmsg_len			= fdset->hdr.msg_controllen;
	cmsg->cmsg_level		= SOL_SOCKET;
	cmsg->cmsg_type			= SCM_RIGHTS;

	return (int *)CMSG_DATA(cmsg);
}

int send_fd(int sock, struct sockaddr_un *saddr, int len, int fd)
{
	struct scm_fdset fdset;
	int *cmsg_data;

	cmsg_data = scm_fdset_init(&fdset, saddr, len);
	scm_fdset_init_chunk(&fdset, 1);
	*cmsg_data = fd;

	return sys_sendmsg(sock, &fdset.hdr, 0);
}

int recv_fd(int sock)
{
	struct scm_fdset fdset;
	struct cmsghdr *cmsg;
	int *cmsg_data;
	int ret;

	cmsg_data = scm_fdset_init(&fdset, NULL, 0);
	scm_fdset_init_chunk(&fdset, 1);

	ret = sys_recvmsg(sock, &fdset.hdr, 0);
	if (ret < 0)
		return ret;

	cmsg = CMSG_FIRSTHDR(&fdset.hdr);
	if (!cmsg || (cmsg->cmsg_type != SCM_RIGHTS))
		return -2;

	return *cmsg_data;
}

