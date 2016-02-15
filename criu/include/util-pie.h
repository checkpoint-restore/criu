#ifndef __CR_UTIL_NET_H__
#define __CR_UTIL_NET_H__

#include <sys/socket.h>
#include <sys/un.h>

#include "asm/types.h"

#define UNIX_PATH_MAX (sizeof(struct sockaddr_un) - \
			(size_t)((struct sockaddr_un *) 0)->sun_path)

#ifndef SO_PEEK_OFF
#define SO_PEEK_OFF            42
#endif

/*
 * Because of kernel doing kmalloc for user data passed
 * in SCM messages, and there is kernel's SCM_MAX_FD as a limit
 * for descriptors passed at once we're trying to reduce
 * the pressue on kernel memory manager and use predefined
 * known to work well size of the message buffer.
 */
#define CR_SCM_MSG_SIZE		(1024)
#define CR_SCM_MAX_FD		(252)

struct fd_opts {
	char flags;
	struct {
		u32 uid;
		u32 euid;
		u32 signum;
		u32 pid_type;
		u32 pid;
	} fown;
};

struct scm_fdset {
	struct msghdr	hdr;
	struct iovec	iov;
	char		msg_buf[CR_SCM_MSG_SIZE];
	struct fd_opts	opts[CR_SCM_MAX_FD];
};

extern int send_fds(int sock, struct sockaddr_un *saddr, int saddr_len,
		int *fds, int nr_fds, bool with_flags);
extern int recv_fds(int sock, int *fds, int nr_fds, struct fd_opts *opts);

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

extern int open_detach_mount(char *dir);

#endif /* __CR_UTIL_NET_H__ */
