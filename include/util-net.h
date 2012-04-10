#ifndef UTIL_NET_H_
#define UTIL_NET_H_

#include <sys/socket.h>
#include <sys/un.h>

#define UNIX_PATH_MAX (sizeof(struct sockaddr_un) - \
			(size_t)((struct sockaddr_un *) 0)->sun_path)

#ifndef SO_PEEK_OFF
#define SO_PEEK_OFF            42
#endif

/*
 * Because of kernel doing kmalloc for user data passed
 * in SCM messages, and there is SCM_MAX_FD as a limit
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
	char		msg[CR_SCM_MAX_FD];
};

extern int send_fds(int sock, struct sockaddr_un *saddr, int saddr_len,
		int *fds, int nr_fds, bool with_flags);
extern int recv_fds(int sock, int *fds, int nr_fds, char *flags);

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
