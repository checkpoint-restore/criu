#include <unistd.h>
#include <inttypes.h>

#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "common/config.h"
#include "common/compiler.h"
#include "types.h"
#include "protobuf.h"
#include "images/sa.pb-c.h"
#include "images/timer.pb-c.h"
#include "images/creds.pb-c.h"
#include "images/core.pb-c.h"
#include "images/pagemap.pb-c.h"

#include "imgset.h"
#include "parasite-syscall.h"
#include "parasite.h"
#include "crtools.h"
#include "namespaces.h"
#include "kerndat.h"
#include "pstree.h"
#include "posix-timer.h"
#include "mem.h"
#include "criu-log.h"
#include "vma.h"
#include "proc_parse.h"
#include "aio.h"
#include "fault-injection.h"
#include <compel/plugins/std/syscall-codes.h>
#include "signal.h"
#include "sigframe.h"

#include <string.h>
#include <stdlib.h>
#include <elf.h>

#include "dump.h"
#include "restorer.h"

#include "infect.h"
#include "infect-rpc.h"
#include "pie/parasite-blob.h"


int parasite_dump_itimers_seized(struct parasite_ctl *ctl, struct pstree_item *item)
{
	CoreEntry *core = item->core[0];
	struct parasite_dump_itimers_args *args;
	int ret;

	args = compel_parasite_args(ctl, struct parasite_dump_itimers_args);

	ret = compel_rpc_call_sync(PARASITE_CMD_DUMP_ITIMERS, ctl);
	if (ret < 0)
		return ret;

	encode_itimer((&args->real), (core->tc->timers->real));			\
	encode_itimer((&args->virt), (core->tc->timers->virt));			\
	encode_itimer((&args->prof), (core->tc->timers->prof));			\

	return 0;
}

static int core_alloc_posix_timers(TaskTimersEntry *tte, int n,
		PosixTimerEntry **pte)
{
	int sz;

	/*
	 * Will be free()-ed in core_entry_free()
	 */

	sz = n * (sizeof(PosixTimerEntry *) + sizeof(PosixTimerEntry));
	tte->posix = xmalloc(sz);
	if (!tte->posix)
		return -1;

	tte->n_posix = n;
	*pte = (PosixTimerEntry *)(tte->posix + n);
	return 0;
}

static void encode_posix_timer(struct posix_timer *v,
		struct proc_posix_timer *vp, PosixTimerEntry *pte)
{
	pte->it_id = vp->spt.it_id;
	pte->clock_id = vp->spt.clock_id;
	pte->si_signo = vp->spt.si_signo;
	pte->it_sigev_notify = vp->spt.it_sigev_notify;
	pte->sival_ptr = encode_pointer(vp->spt.sival_ptr);

	pte->overrun = v->overrun;

	pte->isec = v->val.it_interval.tv_sec;
	pte->insec = v->val.it_interval.tv_nsec;
	pte->vsec = v->val.it_value.tv_sec;
	pte->vnsec = v->val.it_value.tv_nsec;
}

int parasite_dump_posix_timers_seized(struct proc_posix_timers_stat *proc_args,
		struct parasite_ctl *ctl, struct pstree_item *item)
{
	CoreEntry *core = item->core[0];
	TaskTimersEntry *tte = core->tc->timers;
	PosixTimerEntry *pte;
	struct proc_posix_timer *temp;
	struct parasite_dump_posix_timers_args *args;
	int args_size;
	int ret = 0;
	int i;

	if (core_alloc_posix_timers(tte, proc_args->timer_n, &pte))
		return -1;

	args_size = posix_timers_dump_size(proc_args->timer_n);
	args = compel_parasite_args_s(ctl, args_size);
	args->timer_n = proc_args->timer_n;

	i = 0;
	list_for_each_entry(temp, &proc_args->timers, list) {
		args->timer[i].it_id = temp->spt.it_id;
		i++;
	}

	ret = compel_rpc_call_sync(PARASITE_CMD_DUMP_POSIX_TIMERS, ctl);
	if (ret < 0)
		goto end_posix;

	i = 0;
	list_for_each_entry(temp, &proc_args->timers, list) {
		posix_timer_entry__init(&pte[i]);
		encode_posix_timer(&args->timer[i], temp, &pte[i]);
		tte->posix[i] = &pte[i];
		i++;
	}

end_posix:
	free_posix_timers(proc_args);
	return ret;
}

