#include "asm/types.h"
#include "syscall-32.h"

#define SYS_SOCKET	1		/* sys_socket(2)		*/
#define SYS_BIND	2		/* sys_bind(2)			*/
#define SYS_CONNECT	3		/* sys_connect(2)		*/
#define SYS_SENDTO	11		/* sys_sendto(2)		*/
#define SYS_RECVFROM	12		/* sys_recvfrom(2)		*/
#define SYS_SHUTDOWN	13		/* sys_shutdown(2)		*/
#define SYS_SETSOCKOPT	14		/* sys_setsockopt(2)		*/
#define SYS_GETSOCKOPT	15		/* sys_getsockopt(2)		*/
#define SYS_SENDMSG	16		/* sys_sendmsg(2)		*/
#define SYS_RECVMSG	17		/* sys_recvmsg(2)		*/

long sys_socket(int domain, int type, int protocol)
{
	uint32_t a[] = { (uint32_t)domain, (uint32_t)type, (uint32_t)protocol };
	return sys_socketcall(SYS_SOCKET, (unsigned long *)a);
}

long sys_connect(int sockfd, struct sockaddr *addr, int addrlen)
{
	uint32_t a[] = {(uint32_t)sockfd, (uint32_t)addr, (uint32_t)addrlen};
	return sys_socketcall(SYS_CONNECT, (unsigned long *)a);
}

long sys_sendto(int sockfd, void *buff, size_t len, unsigned int flags, struct sockaddr *addr, int addr_len)
{
	uint32_t a[] = {(uint32_t)sockfd, (uint32_t)buff, (uint32_t)len, (uint32_t)flags, (uint32_t)addr, (uint32_t)addr_len};
	return sys_socketcall(SYS_SENDTO, (unsigned long *)a);
}

long sys_recvfrom(int sockfd, void *ubuf, size_t size, unsigned int flags, struct sockaddr *addr, int *addr_len)
{
	uint32_t a[] = {(uint32_t)sockfd, (uint32_t)ubuf, (uint32_t)size, (uint32_t)flags, (uint32_t)addr, (uint32_t)addr_len};
	return sys_socketcall(SYS_RECVFROM, (unsigned long *)a);
}

long sys_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	uint32_t a[] = {(uint32_t)sockfd, (uint32_t)msg, (uint32_t)flags};
	return sys_socketcall(SYS_SENDMSG, (unsigned long *)a);
}

long sys_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	uint32_t a[] = {(uint32_t)sockfd, (uint32_t)msg, (uint32_t)flags};
	return sys_socketcall(SYS_RECVMSG, (unsigned long *)a);
}

long sys_shutdown(int sockfd, int how)
{
	uint32_t a[] = {(uint32_t)sockfd, (uint32_t)how};
	return sys_socketcall(SYS_SHUTDOWN, (unsigned long *)a);
}

long sys_bind(int sockfd, const struct sockaddr *addr, int addrlen)
{
	uint32_t a[] = {(uint32_t)sockfd, (uint32_t)addr, (uint32_t)addrlen};
	return sys_socketcall(SYS_BIND, (unsigned long *)a);
}

long sys_setsockopt(int sockfd, int level, int optname, const void *optval, unsigned int optlen)
{
	uint32_t a[] = {(uint32_t)sockfd, (uint32_t)level, (uint32_t)optname, (uint32_t)optval, (uint32_t)optlen};
	return sys_socketcall(SYS_SETSOCKOPT, (unsigned long *)a);
}

long sys_getsockopt(int sockfd, int level, int optname, const void *optval, unsigned int *optlen)
{
	uint32_t a[] = {(uint32_t)sockfd, (uint32_t)level, (uint32_t)optname, (uint32_t)optval, (uint32_t)optlen};
	return sys_socketcall(SYS_GETSOCKOPT, (unsigned long *)a);
}

#define SHMAT		21

long sys_shmat(int shmid, void *shmaddr, int shmflag)
{
	return sys_ipc(SHMAT, shmid, shmflag, 0, shmaddr, 0);
}

long sys_pread(unsigned int fd, char *ubuf, uint32_t count, uint64_t pos)
{
	return sys_pread64(fd, ubuf, count, (uint32_t)(pos & 0xffffffffu), (uint32_t)(pos >> 32));
}
