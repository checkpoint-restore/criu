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

#ifdef SCM_FDSET_HAS_OPTS
struct fd_opts {
	char flags;
	struct {
		uint32_t uid;
		uint32_t euid;
		uint32_t signum;
		uint32_t pid_type;
		uint32_t pid;
	} fown;
};
#endif

struct scm_fdset {
	struct msghdr	hdr;
	struct iovec	iov;
	char		msg_buf[CR_SCM_MSG_SIZE];
#ifdef SCM_FDSET_HAS_OPTS
	struct fd_opts	opts[CR_SCM_MAX_FD];
#else
	char		dummy;
#endif
};

#ifndef F_GETOWNER_UIDS
#define F_GETOWNER_UIDS	17
#endif

extern int send_fds(int sock, struct sockaddr_un *saddr, int len,
		    int *fds, int nr_fds, bool with_flags);

#ifdef SCM_FDSET_HAS_OPTS
extern int recv_fds(int sock, int *fds, int nr_fds, struct fd_opts *opts);
#else
extern int recv_fds(int sock, int *fds, int nr_fds, char *opts);
#endif

static inline int send_fd(int sock, struct sockaddr_un *saddr, int saddr_len, int fd)
{
	return send_fds(sock, saddr, saddr_len, &fd, 1, false);
}

static inline int recv_fd(int sock)
{
	int fd, ret;

	ret = recv_fds(sock, &fd, 1, NULL);
	if (ret)
		return -1;

	return fd;
}

#endif
