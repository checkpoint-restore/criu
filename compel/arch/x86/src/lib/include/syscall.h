#ifndef __COMPEL_SYSCALL_H__
#define __COMPEL_SYSCALL_H__
#define __NR(syscall, compat)	((compat) ? __NR32_##syscall : __NR_##syscall)
#endif
