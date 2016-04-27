#ifndef __CR_UFFD_H_
#define __CR_UFFD_H_

struct task_restore_args;
extern int setup_uffd(struct task_restore_args *task_args, int pid);

#endif /* __CR_UFFD_H_ */
