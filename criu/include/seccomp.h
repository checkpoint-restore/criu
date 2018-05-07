#ifndef __CR_SECCOMP_H__
#define __CR_SECCOMP_H__

#include <linux/seccomp.h>
#include <linux/filter.h>

#include "images/seccomp.pb-c.h"
#include "images/core.pb-c.h"

#ifndef SECCOMP_MODE_DISABLED
#define SECCOMP_MODE_DISABLED 0
#endif

#ifndef SECCOMP_MODE_STRICT
#define SECCOMP_MODE_STRICT 1
#endif

#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif

#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif

#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC 1
#endif

struct thread_restore_args;
struct task_restore_args;

struct seccomp_info {
	struct seccomp_info	*prev;
	int			id;
	SeccompFilter		filter;
};

extern int collect_seccomp_filters(void);
extern int prepare_seccomp_filters(void);

extern int seccomp_read_image(void);
extern int seccomp_prepare_threads(struct pstree_item *item, struct task_restore_args *ta);
extern void seccomp_rst_reloc(struct thread_restore_args *thread_arg);

#endif
