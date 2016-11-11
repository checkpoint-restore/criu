/*
 * plugin-fds.h -- API for fds compel plugin
 */

#ifndef __COMPEL_PLUGIN_FDS_H__
#define __COMPEL_PLUGIN_FDS_H__

#include <sys/un.h>

#include "common/scm.h"

static inline int send_fd(int sock, struct sockaddr_un *saddr, int saddr_len, int fd)
{
	return send_fds(sock, saddr, saddr_len, &fd, 1, false);
}

#endif /* __COMPEL_PLUGIN_FDS_H__ */
