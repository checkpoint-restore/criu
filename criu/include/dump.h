#ifndef __CR_INC_DUMP_H__
#define __CR_INC_DUMP_H__
#include "asm/dump.h"
#include "images/inventory.pb-c.h"

struct pstree_item;

extern int arch_set_thread_regs(struct pstree_item *item, bool with_threads);

/* Core dump functions exposed for clone-dump phased migration */
extern int collect_file_locks(void);
extern int collect_pstree_ids_predump(void);
extern int cr_dump_finish(int ret);
extern int cr_dump_init(pid_t pid, InventoryEntry *he, const char *banner);
extern int cr_dump_post_task_operations(InventoryEntry *he);
extern int dump_one_task(struct pstree_item *item, InventoryEntry *parent_ie);
extern int pre_dump_one_task(struct pstree_item *item, InventoryEntry *parent_ie);

#endif
