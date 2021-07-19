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
struct pstree_item;
struct rb_node;

/*
 * seccomp filters are bound to @current->seccomp.filter
 * in the kernel, ie they are per thread structures.
 *
 * If filter is assigned then every subsequent call
 * to fork() makes a copy of this @current->seccomp.filter
 * pointer into child process.
 *
 * The thread group can share a filter if the filter
 * is assigned with SECCOMP_FILTER_FLAG_TSYNC on group
 * which has no filters yet.
 */
struct seccomp_filter_chain {
	struct seccomp_filter_chain *prev;
	SeccompFilter filter;
};

struct seccomp_entry {
	struct rb_node node;
	struct seccomp_entry *next;
	pid_t tid_real;
	size_t img_filter_pos;
	unsigned int mode;

	struct seccomp_filter_chain *chain;
	size_t nr_chains;
};

extern struct seccomp_entry *seccomp_lookup(pid_t tid_real, bool create, bool mandatory);
#define seccomp_find_entry(tid_real) seccomp_lookup(tid_real, false, true)
extern int seccomp_collect_entry(pid_t tid_real, unsigned int mode);
extern void seccomp_free_entries(void);
extern int seccomp_dump_thread(pid_t tid_real, ThreadCoreEntry *thread_core);
extern int seccomp_collect_dump_filters(void);

extern int seccomp_read_image(void);
extern int seccomp_prepare_threads(struct pstree_item *item, struct task_restore_args *ta);
extern void seccomp_rst_reloc(struct thread_restore_args *thread_arg);

#endif
