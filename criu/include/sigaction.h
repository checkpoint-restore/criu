#ifndef __CR_SIGACTION_H__
#define __CR_SIGACTION_H__


#include <sys/un.h>
#include <sys/time.h>

#include <unistd.h>
#include <inttypes.h>

#include "parasite.h"
#include "parasite-syscall.h"
#include "pstree.h"
#include "sigframe.h" //TaskCoreEntry, SaEntry

#include "image.h"
#include "img-remote.h"
#include "images/core.pb-c.h"
#include "images/sa.pb-c.h"
#include "infect.h"
#include "infect-rpc.h"
#include "parasite.h"
#include "util-pie.h"

#include <compel/compel.h>
#include "restore.h"
#include "restorer.h"




extern rt_sigaction_t sigchld_act;

int parasite_dump_sigacts_seized(struct parasite_ctl *ctl, struct pstree_item *item);

int prepare_sigactions(CoreEntry *core);

#endif
