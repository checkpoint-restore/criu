#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>

#include "compiler.h"
#include "memcpy_64.h"
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

int send_fds(int sock, struct sockaddr_un *saddr, int len, int *fds, int nr_fds)
{
	struct scm_fdset fdset;
	int *cmsg_data;
	int i, min_fd, ret;

	cmsg_data = scm_fdset_init(&fdset, saddr, len);
	for (i = 0; i < nr_fds; i += min_fd) {
		min_fd = min(CR_SCM_MAX_FD, nr_fds - i);
		scm_fdset_init_chunk(&fdset, min_fd);
		builtin_memcpy(cmsg_data, &fds[i], sizeof(int) * min_fd);

		ret = sys_sendmsg(sock, &fdset.hdr, 0);
		if (ret <= 0)
			return ret ? : -1;
	}

	return 0;
}

int recv_fds(int sock, int *fds, int nr_fds)
{
	struct scm_fdset fdset;
	struct cmsghdr *cmsg;
	int *cmsg_data;
	int ret;
	int i, min_fd;

	cmsg_data = scm_fdset_init(&fdset, NULL, 0);
	for (i = 0; i < nr_fds; i += min_fd) {
		min_fd = min(CR_SCM_MAX_FD, nr_fds - i);
		scm_fdset_init_chunk(&fdset, min_fd);

		ret = sys_recvmsg(sock, &fdset.hdr, 0);
		if (ret <= 0)
			return ret ? : -1;

		cmsg = CMSG_FIRSTHDR(&fdset.hdr);
		if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS)
			return -EINVAL;

		min_fd = (cmsg->cmsg_len - sizeof(struct cmsghdr)) / sizeof(int);
		/*
		 * In case if kernel screwed the recepient, most probably
		 * the caller stack frame will be overwriten, just scream
		 * and exit.
		 *
		 * FIXME Need to sanitize util.h to be able to include it
		 * into files which do not have glibc and a couple of
		 * sys_write_ helpers. Meawhile opencoded BUG_ON here.
		 */
		if (unlikely(min_fd > CR_SCM_MAX_FD))
			*(volatile unsigned long *)NULL = 0xdead0000 + __LINE__;
		if (unlikely(min_fd <= 0))
			return -1;
		builtin_memcpy(&fds[i], cmsg_data, sizeof(int) * min_fd);
	}

	return 0;
}

