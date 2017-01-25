#ifndef __COMMON_SCM_H__
#define __COMMON_SCM_H__

#include <stdint.h>
#include <stdbool.h>
#include <sys/un.h>

/*
 * Because of kernel doing kmalloc for user data passed
 * in SCM messages, and there is kernel's SCM_MAX_FD as a limit
 * for descriptors passed at once we're trying to reduce
 * the pressue on kernel memory manager and use predefined
 * known to work well size of the message buffer.
 */
#define CR_SCM_MSG_SIZE		(1024)
#define CR_SCM_MAX_FD		(252)

struct scm_fdset {
	struct msghdr	hdr;
	struct iovec	iov;
	char		msg_buf[CR_SCM_MSG_SIZE];
};

#ifndef F_GETOWNER_UIDS
#define F_GETOWNER_UIDS	17
#endif

extern int send_fds(int sock, struct sockaddr_un *saddr, int len,
		int *fds, int nr_fds, void *data, unsigned ch_size);
extern int __recv_fds(int sock, int *fds, int nr_fds,
		void *data, unsigned ch_size, int flags);
static inline int recv_fds(int sock, int *fds, int nr_fds,
		void *data, unsigned ch_size)
{
	return __recv_fds(sock, fds, nr_fds, data, ch_size, 0);
}

static inline int send_fd(int sock, struct sockaddr_un *saddr, int saddr_len, int fd)
{
	return send_fds(sock, saddr, saddr_len, &fd, 1, NULL, 0);
}

static inline int recv_fd(int sock)
{
	int fd, ret;

	ret = recv_fds(sock, &fd, 1, NULL, 0);
	if (ret)
		return -1;

	return fd;
}

#endif
