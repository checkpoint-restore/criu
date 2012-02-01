#ifndef CR_SYSCALL_CODES_H_
#define CR_SYSCALL_CODES_H_

#ifdef CONFIG_X86_64

#define __NR_read		0
#define __NR_write		1
#define __NR_open		2
#define __NR_close		3
#define __NR_lseek		8
#define __NR_mmap		9
#define __NR_mprotect		10
#define __NR_munmap		11
#define __NR_brk		12
#define __NR_rt_sigaction	13
#define __NR_rt_sigreturn	15
#define __NR_mincore		27
#define __NR_dup		32
#define __NR_dup2		33
#define __NR_pause		34
#define __NR_nanosleep		35
#define __NR_getitimer		36
#define __NR_setitimer		38
#define __NR_getpid		39
#define __NR_socket		41
#define __NR_sendmsg		46
#define __NR_recvmsg		47
#define __NR_bind		49
#define __NR_clone		56
#define __NR_exit		60
#define __NR_wait4		61
#define __NR_kill		62
#define __NR_flock		73
#define __NR_unlink		87
#define __NR_setresuid		117
#define __NR_setresgid		119
#define __NR_setfsuid		122
#define __NR_setfsgid		123
#define __NR_capset		126
#define __NR_tgkill		131
#define __NR__sysctl		156
#define __NR_prctl		157
#define __NR_arch_prctl		158
#define __NR_gettid		186
#define __NR_futex		202
#define __NR_set_thread_area	205
#define __NR_get_thread_area	211
#define __NR_restart_syscall	219
#define __NR_msync		227
#define __NR_setns		308

#else /* CONFIG_X86_64 */
# error x86-32 bit mode not yet implemented
#endif /* CONFIG_X86_64 */

#endif /* CR_SYSCALL_CODES_H_ */
