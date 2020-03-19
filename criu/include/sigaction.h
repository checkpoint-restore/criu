#ifndef __CR_SIGACTION_H__
#define __CR_SIGACTION_H__

#include "parasite-syscall.h"
#include "pstree.h"
#include "images/core.pb-c.h"
#include <compel/plugins/std/syscall-codes.h>

extern rt_sigaction_t sigchld_act;

int parasite_dump_sigacts_seized(struct parasite_ctl *ctl, struct pstree_item *item);
int prepare_sigactions(CoreEntry *core);
#endif
