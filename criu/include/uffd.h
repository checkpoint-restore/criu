#ifndef __CR_UFFD_H_
#define __CR_UFFD_H_

struct task_restore_args;
extern int setup_uffd(int pid, struct task_restore_args *task_args);
extern int lazy_pages_setup_zombie(void);
extern int prepare_lazy_pages_socket(void);

#endif /* __CR_UFFD_H_ */
