#ifndef __CR_UFFD_H_
#define __CR_UFFD_H_

struct task_restore_args;
extern int setup_uffd(int pid, struct task_restore_args *task_args);

#endif /* __CR_UFFD_H_ */
