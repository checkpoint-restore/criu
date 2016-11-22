#ifndef __CR_UTIL_NET_H__
#define __CR_UTIL_NET_H__

#include <sys/socket.h>
#include <sys/un.h>

#define UNIX_PATH_MAX (sizeof(struct sockaddr_un) - \
			(size_t)((struct sockaddr_un *) 0)->sun_path)

#ifndef SO_PEEK_OFF
#define SO_PEEK_OFF            42
#endif

#include "common/scm.h"

extern int open_detach_mount(char *dir);

#endif /* __CR_UTIL_NET_H__ */
