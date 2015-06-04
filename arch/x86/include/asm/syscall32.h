#ifndef __CR_SYSCALL32_H__
#define __CR_SYSCALL32_H__

extern long sys_socket(int domain, int type, int protocol);
extern long sys_connect(int sockfd, struct sockaddr *addr, int addrlen);
extern long sys_sendto(int sockfd, void *buff, size_t len, unsigned int flags, struct sockaddr *addr, int addr_len);
extern long sys_recvfrom(int sockfd, void *ubuf, size_t size, unsigned int flags, struct sockaddr *addr, int *addr_len);
extern long sys_sendmsg(int sockfd, const struct msghdr *msg, int flags);
extern long sys_recvmsg(int sockfd, struct msghdr *msg, int flags);
extern long sys_shutdown(int sockfd, int how);
extern long sys_bind(int sockfd, const struct sockaddr *addr, int addrlen);
extern long sys_setsockopt(int sockfd, int level, int optname, const void *optval, unsigned int optlen);
extern long sys_getsockopt(int sockfd, int level, int optname, const void *optval, unsigned int *optlen);
extern long sys_shmat(int shmid, void *shmaddr, int shmflag);
extern long sys_pread(unsigned int fd, char *ubuf, u32 count, u64 pos);

/*
 * For x86_32 __NR_mmap inside the kernel represents old_mmap system
 * call, but since we didn't use it yet lets go further and simply
 * define own alias for __NR_mmap2 which would allow us to unify code
 * between 32 and 64 bits version.
 */
#define __NR_mmap __NR_mmap2

#endif /* __CR_SYSCALL32_H__ */
