#ifndef __CR_UFFD_H_
#define __CR_UFFD_H_

#include "config.h"
#include "restorer.h"

#ifdef CONFIG_HAS_UFFD

#include <syscall.h>
#include <linux/userfaultfd.h>

#ifndef __NR_userfaultfd
#error "missing __NR_userfaultfd definition"
#endif

extern int setup_uffd(struct task_restore_args *task_args, int pid);
#else
static inline int setup_uffd(struct task_restore_args *task_args, int pid) { return 0; }

#endif /* CONFIG_HAS_UFFD */

#endif /* __CR_UFFD_H_ */
