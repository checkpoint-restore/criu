#ifndef __CR_UFFD_H_
#define __CR_UFFD_H_

#include "config.h"

#ifdef CONFIG_HAS_UFFD

#include <syscall.h>
#include <linux/userfaultfd.h>

#ifndef __NR_userfaultfd
#error "missing __NR_userfaultfd definition"
#endif
#endif /* CONFIG_HAS_UFFD */

#endif /* __CR_UFFD_H_ */
