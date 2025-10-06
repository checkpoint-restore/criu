#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif

#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif

#ifndef PID_FS_MAGIC
#define PID_FS_MAGIC 0x50494446
#endif

int pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

int pidfd_getfd(int pidfd, int targetfd, unsigned int flags)
{
	return syscall(__NR_pidfd_getfd, pidfd, targetfd, flags);
}

int pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags)
{
	return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
}
