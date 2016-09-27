#ifndef __CR_PID_H__
#define __CR_PID_H__

#include "stdbool.h"
#include "rbtree.h"

struct pid {
	/*
	 * The @real pid is used to fetch tasks during dumping stage,
	 * This is a global pid seen from the context where the dumping
	 * is running.
	 */
	pid_t real;

	/*
	 * The @virt pid is one which used in the image itself and keeps
	 * the pid value to be restored. This pid fetched from the
	 * dumpee context, because the dumpee might have own pid namespace.
	 */
	pid_t virt;

	int state;	/* TASK_XXX constants */

	struct rb_node node;
};

#define TASK_UNDEF		0x0
#define TASK_ALIVE		0x1
#define TASK_DEAD		0x2
#define TASK_STOPPED		0x3
#define TASK_HELPER		0x4
#define TASK_THREAD		0x5
#define TASK_ZOMBIE		0x6

/*
 * When we have to restore a shared resource, we mush select which
 * task should do it, and make other(s) wait for it. In order to
 * avoid deadlocks, always make task with lower pid be the restorer.
 */
static inline bool pid_rst_prio(unsigned pid_a, unsigned pid_b)
{
	return pid_a < pid_b;
}

#endif /* __CR_PID_H__ */
