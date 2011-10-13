#ifndef SEIZE_H_
#define SEIZE_H_

#include <sys/ptrace.h>

int seize_task(pid_t pid);
int unseize_task(pid_t pid);

#endif /* SEIZE_H_ */
