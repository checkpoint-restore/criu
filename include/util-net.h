#ifndef UTIL_NET_H_
#define UTIL_NET_H_

#define UNIX_PATH_MAX (sizeof(struct sockaddr_un) - \
			(size_t)((struct sockaddr_un *) 0)->sun_path)

extern int send_fd(int sock, struct sockaddr_un *saddr, int len, int fd);
extern int recv_fd(int sock);
#endif
