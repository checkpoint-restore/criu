#ifndef __ASM_PROLOGUE_H__
#define __ASM_PROLOGUE_H__

#ifndef __ASSEMBLY__

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>

#define sys_recv(sockfd, ubuf, size, flags) sys_recvfrom(sockfd, ubuf, size, flags, NULL, NULL)

typedef struct prologue_init_args {
	struct sockaddr_un ctl_sock_addr;
	unsigned int ctl_sock_addr_len;

	unsigned int arg_s;
	void *arg_p;

	void *sigframe;
} prologue_init_args_t;

#endif /* __ASSEMBLY__ */

/*
 * Reserve enough space for sigframe.
 *
 * FIXME It is rather should be taken from sigframe header.
 */
#define PROLOGUE_SGFRAME_SIZE 4096

#define PROLOGUE_INIT_ARGS_SIZE 1024

#endif /* __ASM_PROLOGUE_H__ */