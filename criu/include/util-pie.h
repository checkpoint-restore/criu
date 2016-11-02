#ifndef __CR_UTIL_NET_H__
#define __CR_UTIL_NET_H__

#include <sys/socket.h>
#include <sys/un.h>

#define UNIX_PATH_MAX (sizeof(struct sockaddr_un) - \
			(size_t)((struct sockaddr_un *) 0)->sun_path)

#ifndef SO_PEEK_OFF
#define SO_PEEK_OFF            42
#endif

#define SCM_FDSET_HAS_OPTS

#include "common/scm.h"

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
