#ifndef __CR_SIGACT_H__
#define __CR_SIGACT_H__

#include "images/core.pb-c.h"

extern rt_sigaction_t sigchld_act;

struct parasite_ctl;
struct pstree_item;

extern int prepare_sigactions(CoreEntry *core);
extern int parasite_dump_sigacts_seized(struct parasite_ctl *ctl, struct pstree_item *);

#endif
