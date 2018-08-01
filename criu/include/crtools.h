#ifndef __CR_CRTOOLS_H__
#define __CR_CRTOOLS_H__

#include <sys/types.h>

#include "common/list.h"
#include "servicefd.h"

#include "images/inventory.pb-c.h"

#define CR_FD_PERM		(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

extern int check_img_inventory(void);
extern int write_img_inventory(InventoryEntry *he);
extern int invertory_save_uptime(InventoryEntry *he);
extern InventoryEntry *get_parent_inventory(void);
extern int prepare_inventory(InventoryEntry *he);
struct pprep_head {
	int (*actor)(struct pprep_head *);
	struct pprep_head *next;
};
extern void add_post_prepare_cb(struct pprep_head *);
extern bool deprecated_ok(char *what);
extern int cr_dump_tasks(pid_t pid);
extern int cr_pre_dump_tasks(pid_t pid);
extern int cr_restore_tasks(void);
extern int convert_to_elf(char *elf_path, int fd_core);
extern int cr_check(void);
extern int cr_dedup(void);
extern int cr_lazy_pages(bool daemon);

extern int check_add_feature(char *arg);
extern void pr_check_features(const char *offset, const char *sep, int width);

#define PPREP_HEAD_INACTIVE	((struct pprep_head *)-1)

#define add_post_prepare_cb_once(phead) do {		 \
		if ((phead)->next == PPREP_HEAD_INACTIVE)\
			add_post_prepare_cb(phead);	 \
	} while (0)

#define MAKE_PPREP_HEAD(name) struct pprep_head name = {	\
			.next = PPREP_HEAD_INACTIVE,		\
			.actor = name##_cb,			\
	}

#endif /* __CR_CRTOOLS_H__ */
