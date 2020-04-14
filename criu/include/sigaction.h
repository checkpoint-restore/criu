#ifndef __CR_SIGACTION_H__
#define __CR_SIGACTION_H__

#include "pstree.h" //parasite_ctl, pstree_item

extern rt_sigaction_t sigchld_act;

int parasite_dump_sigacts_seized(struct parasite_ctl *ctl, struct pstree_item *item);
int prepare_sigactions(CoreEntry *core);
#endif
