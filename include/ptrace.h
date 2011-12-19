#ifndef SEIZE_H_
#define SEIZE_H_

#include <sys/ptrace.h>

extern int seize_task(pid_t pid);
extern int unseize_task(pid_t pid);
extern int ptrace_peek_area(pid_t pid, void *dst, void *addr, long bytes);
extern int ptrace_poke_area(pid_t pid, void *src, void *addr, long bytes);
extern int ptrace_show_area(pid_t pid, void *addr, long bytes);
extern int ptrace_show_area_r(pid_t pid, void *addr, long bytes);

#endif /* SEIZE_H_ */
