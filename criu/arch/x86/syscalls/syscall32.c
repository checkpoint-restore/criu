#include "asm/types.h"
#include "syscall.h"

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
	u32 a[] = { (u32)domain, (u32)type, (u32)protocol };
	return sys_socketcall(SYS_SOCKET, (unsigned long *)a);
}

long sys_connect(int sockfd, struct sockaddr *addr, int addrlen)
{
	u32 a[] = {(u32)sockfd, (u32)addr, (u32)addrlen};
	return sys_socketcall(SYS_CONNECT, (unsigned long *)a);
}

long sys_sendto(int sockfd, void *buff, size_t len, unsigned int flags, struct sockaddr *addr, int addr_len)
{
	u32 a[] = {(u32)sockfd, (u32)buff, (u32)len, (u32)flags, (u32)addr, (u32)addr_len};
	return sys_socketcall(SYS_SENDTO, (unsigned long *)a);
}

long sys_recvfrom(int sockfd, void *ubuf, size_t size, unsigned int flags, struct sockaddr *addr, int *addr_len)
{
	u32 a[] = {(u32)sockfd, (u32)ubuf, (u32)size, (u32)flags, (u32)addr, (u32)addr_len};
	return sys_socketcall(SYS_RECVFROM, (unsigned long *)a);
}

long sys_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	u32 a[] = {(u32)sockfd, (u32)msg, (u32)flags};
	return sys_socketcall(SYS_SENDMSG, (unsigned long *)a);
}

long sys_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	u32 a[] = {(u32)sockfd, (u32)msg, (u32)flags};
	return sys_socketcall(SYS_RECVMSG, (unsigned long *)a);
}

long sys_shutdown(int sockfd, int how)
{
	u32 a[] = {(u32)sockfd, (u32)how};
	return sys_socketcall(SYS_SHUTDOWN, (unsigned long *)a);
}

long sys_bind(int sockfd, const struct sockaddr *addr, int addrlen)
{
	u32 a[] = {(u32)sockfd, (u32)addr, (u32)addrlen};
	return sys_socketcall(SYS_BIND, (unsigned long *)a);
}

long sys_setsockopt(int sockfd, int level, int optname, const void *optval, unsigned int optlen)
{
	u32 a[] = {(u32)sockfd, (u32)level, (u32)optname, (u32)optval, (u32)optlen};
	return sys_socketcall(SYS_SETSOCKOPT, (unsigned long *)a);
}

long sys_getsockopt(int sockfd, int level, int optname, const void *optval, unsigned int *optlen)
{
	u32 a[] = {(u32)sockfd, (u32)level, (u32)optname, (u32)optval, (u32)optlen};
	return sys_socketcall(SYS_GETSOCKOPT, (unsigned long *)a);
}

#define SHMAT		21

long sys_shmat(int shmid, void *shmaddr, int shmflag)
{
	return sys_ipc(SHMAT, shmid, shmflag, 0, shmaddr, 0);
}

long sys_pread(unsigned int fd, char *ubuf, u32 count, u64 pos)
{
	return sys_pread64(fd, ubuf, count, (u32)(pos & 0xffffffffu), (u32)(pos >> 32));
}
