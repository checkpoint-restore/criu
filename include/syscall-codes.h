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
#define __NR_mincore		27
#define __NR_dup		32
#define __NR_dup2		33
#define __NR_pause		34
#define __NR_nanosleep		35
#define __NR_getpid		39
#define __NR_exit		60

#else /* CONFIG_X86_64 */
# error x86-32 bit mode not yet implemented
#endif /* CONFIG_X86_64 */

#endif /* CR_SYSCALL_CODES_H_ */
