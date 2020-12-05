#ifndef __CR_SIGACTS_DUMP_H__
#define __CR_SIGACTS_DUMP_H__

#include "common/list.h"
#include "common/config.h"

extern rt_sigaction_t sigchld_act;

extern int parasite_dump_sigacts_seized(struct parasite_ctl *ctl, struct pstree_item *);
extern int prepare_sigactions(CoreEntry *core);
#endif /* __CR_SIGACTS_DUMP_H__ */