#include "types.h"
#include "crtools.h"
#include "infect.h"
#include "protobuf.h"
#include "pstree.h"
#include "posix-timer.h"
#include "parasite.h"
#include "namespaces.h"
#include "rst-malloc.h"
#include "restorer.h"

static inline int timeval_valid(struct timeval *tv)
{
	return (tv->tv_sec >= 0) && ((unsigned long)tv->tv_usec < USEC_PER_SEC);
}

static inline int decode_itimer(char *n, ItimerEntry *ie, struct itimerval *val)
{
	if (ie->isec == 0 && ie->iusec == 0 && ie->vsec == 0 && ie->vusec == 0) {
		memzero_p(val);
		return 0;
	}

	val->it_interval.tv_sec = ie->isec;
	val->it_interval.tv_usec = ie->iusec;

	if (!timeval_valid(&val->it_interval)) {
		pr_err("Invalid timer interval\n");
		return -1;
	}

	if (ie->vsec == 0 && ie->vusec == 0) {
		/*
		 * Remaining time was too short. Set it to
		 * interval to make the timer armed and work.
		 */
		val->it_value.tv_sec = ie->isec;
		val->it_value.tv_usec = ie->iusec;
	} else {
		val->it_value.tv_sec = ie->vsec;
		val->it_value.tv_usec = ie->vusec;
	}

	if (!timeval_valid(&val->it_value)) {
		pr_err("Invalid timer value\n");
		return -1;
	}

	pr_info("Restored %s timer to %" PRId64 ".%" PRId64 " -> %" PRId64 ".%" PRId64 "\n", n,
		(int64_t)val->it_value.tv_sec, (int64_t)val->it_value.tv_usec,
		(int64_t)val->it_interval.tv_sec, (int64_t)val->it_interval.tv_usec);

	return 0;
}

/*
 * Legacy itimers restore from CR_FD_ITIMERS
 */

int prepare_itimers_from_fd(int pid, struct task_restore_args *args)
{
	int ret = -1;
	struct cr_img *img;
	ItimerEntry *ie;

	if (!deprecated_ok("Itimers"))
		return -1;

	img = open_image(CR_FD_ITIMERS, O_RSTR, pid);
	if (!img)
		return -1;

	ret = pb_read_one(img, &ie, PB_ITIMER);
	if (ret < 0)
		goto out;
	ret = decode_itimer("real", ie, &args->itimers[0]);
	itimer_entry__free_unpacked(ie, NULL);
	if (ret < 0)
		goto out;

	ret = pb_read_one(img, &ie, PB_ITIMER);
	if (ret < 0)
		goto out;
	ret = decode_itimer("virt", ie, &args->itimers[1]);
	itimer_entry__free_unpacked(ie, NULL);
	if (ret < 0)
		goto out;

	ret = pb_read_one(img, &ie, PB_ITIMER);
	if (ret < 0)
		goto out;
	ret = decode_itimer("prof", ie, &args->itimers[2]);
	itimer_entry__free_unpacked(ie, NULL);
	if (ret < 0)
		goto out;
out:
	close_image(img);
	return ret;
}

int prepare_itimers(int pid, struct task_restore_args *args, CoreEntry *core)
{
	int ret = 0;
	TaskTimersEntry *tte = core->tc->timers;

	if (!tte)
		return prepare_itimers_from_fd(pid, args);

	ret |= decode_itimer("real", tte->real, &args->itimers[0]);
	ret |= decode_itimer("virt", tte->virt, &args->itimers[1]);
	ret |= decode_itimer("prof", tte->prof, &args->itimers[2]);

	return ret;
}

static inline int timespec_valid(struct timespec *ts)
{
	return (ts->tv_sec >= 0) && ((unsigned long)ts->tv_nsec < NSEC_PER_SEC);
}

static inline int decode_posix_timer(PosixTimerEntry *pte, struct restore_posix_timer *pt)
{
	pt->val.it_interval.tv_sec = pte->isec;
	pt->val.it_interval.tv_nsec = pte->insec;

	if (!timespec_valid(&pt->val.it_interval)) {
		pr_err("Invalid timer interval(posix)\n");
		return -1;
	}

	if (pte->vsec == 0 && pte->vnsec == 0) {
		/*
		 * Remaining time was too short. Set it to
		 * interval to make the timer armed and work.
		 */
		pt->val.it_value.tv_sec = pte->isec;
		pt->val.it_value.tv_nsec = pte->insec;
	} else {
		pt->val.it_value.tv_sec = pte->vsec;
		pt->val.it_value.tv_nsec = pte->vnsec;
	}

	if (!timespec_valid(&pt->val.it_value)) {
		pr_err("Invalid timer value(posix)\n");
		return -1;
	}

	pt->spt.it_id = pte->it_id;
	pt->spt.clock_id = pte->clock_id;
	pt->spt.si_signo = pte->si_signo;
	pt->spt.it_sigev_notify = pte->it_sigev_notify;
	pt->spt.sival_ptr = decode_pointer(pte->sival_ptr);
	pt->spt.notify_thread_id = pte->notify_thread_id;
	pt->overrun = pte->overrun;

	return 0;
}

static int cmp_posix_timer_proc_id(const void *p1, const void *p2)
{
	return ((struct restore_posix_timer *)p1)->spt.it_id - ((struct restore_posix_timer *)p2)->spt.it_id;
}

static void sort_posix_timers(struct task_restore_args *ta)
{
	void *tmem;

	/*
	 * This is required for restorer's create_posix_timers(),
	 * it will probe them one-by-one for the desired ID, since
	 * kernel doesn't provide another API for timer creation
	 * with given ID.
	 */

	if (ta->posix_timers_n > 0) {
		tmem = rst_mem_remap_ptr((unsigned long)ta->posix_timers, RM_PRIVATE);
		qsort(tmem, ta->posix_timers_n, sizeof(struct restore_posix_timer), cmp_posix_timer_proc_id);
	}
}

/*
 * Legacy posix timers restoration from CR_FD_POSIX_TIMERS
 */

int prepare_posix_timers_from_fd(int pid, struct task_restore_args *ta)
{
	struct cr_img *img;
	int ret = -1;
	struct restore_posix_timer *t;

	if (!deprecated_ok("Posix timers"))
		return -1;

	img = open_image(CR_FD_POSIX_TIMERS, O_RSTR, pid);
	if (!img)
		return -1;

	ta->posix_timers_n = 0;
	while (1) {
		PosixTimerEntry *pte;

		ret = pb_read_one_eof(img, &pte, PB_POSIX_TIMER);
		if (ret <= 0)
			break;

		t = rst_mem_alloc(sizeof(struct restore_posix_timer), RM_PRIVATE);
		if (!t)
			break;

		ret = decode_posix_timer(pte, t);
		if (ret < 0)
			break;

		posix_timer_entry__free_unpacked(pte, NULL);
		ta->posix_timers_n++;
	}

	close_image(img);
	if (!ret)
		sort_posix_timers(ta);

	return ret;
}

int prepare_posix_timers(int pid, struct task_restore_args *ta, CoreEntry *core)
{
	int i, ret = -1;
	TaskTimersEntry *tte = core->tc->timers;
	struct restore_posix_timer *t;

	ta->posix_timers = (struct restore_posix_timer *)rst_mem_align_cpos(RM_PRIVATE);

	if (!tte)
		return prepare_posix_timers_from_fd(pid, ta);

	ta->posix_timers_n = tte->n_posix;
	for (i = 0; i < ta->posix_timers_n; i++) {
		t = rst_mem_alloc(sizeof(struct restore_posix_timer), RM_PRIVATE);
		if (!t)
			goto out;

		if (decode_posix_timer(tte->posix[i], t))
			goto out;
	}

	ret = 0;
	sort_posix_timers(ta);
out:
	return ret;
}

static void encode_itimer(struct itimerval *v, ItimerEntry *ie)
{
	ie->isec = v->it_interval.tv_sec;
	ie->iusec = v->it_interval.tv_usec;
	ie->vsec = v->it_value.tv_sec;
	ie->vusec = v->it_value.tv_usec;
}

int parasite_dump_itimers_seized(struct parasite_ctl *ctl, struct pstree_item *item)
{
	CoreEntry *core = item->core[0];
	struct parasite_dump_itimers_args *args;
	int ret;

	args = compel_parasite_args(ctl, struct parasite_dump_itimers_args);

	ret = compel_rpc_call_sync(PARASITE_CMD_DUMP_ITIMERS, ctl);
	if (ret < 0)
		return ret;

	encode_itimer((&args->real), (core->tc->timers->real));
	encode_itimer((&args->virt), (core->tc->timers->virt));
	encode_itimer((&args->prof), (core->tc->timers->prof));

	return 0;
}

static int core_alloc_posix_timers(TaskTimersEntry *tte, int n, PosixTimerEntry **pte)
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

static int encode_notify_thread_id(pid_t rtid, struct pstree_item *item, PosixTimerEntry *pte)
{
	pid_t vtid = 0;
	int i;

	if (rtid == 0)
		return 0;

	if (!(root_ns_mask & CLONE_NEWPID)) {
		/* Non-pid-namespace case */
		pte->notify_thread_id = rtid;
		pte->has_notify_thread_id = true;
		return 0;
	}

	/* Pid-namespace case */
	if (!kdat.has_nspid) {
		pr_err("Have no NSpid support to dump notify thread id in pid namespace\n");
		return -1;
	}

	for (i = 0; i < item->nr_threads; i++) {
		if (item->threads[i].real != rtid)
			continue;

		vtid = item->threads[i].ns[0].virt;
		break;
	}

	if (vtid == 0) {
		pr_err("Unable to convert the notify thread id %d\n", rtid);
		return -1;
	}

	pte->notify_thread_id = vtid;
	pte->has_notify_thread_id = true;
	return 0;
}

static int encode_posix_timer(struct pstree_item *item, struct posix_timer *v, struct proc_posix_timer *vp,
			      PosixTimerEntry *pte)
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

	if (encode_notify_thread_id(vp->spt.notify_thread_id, item, pte))
		return -1;

	return 0;
}

int parasite_dump_posix_timers_seized(struct proc_posix_timers_stat *proc_args, struct parasite_ctl *ctl,
				      struct pstree_item *item)
{
	CoreEntry *core = item->core[0];
	TaskTimersEntry *tte = core->tc->timers;
	PosixTimerEntry *pte;
	struct proc_posix_timer *temp;
	struct parasite_dump_posix_timers_args *args;
	int ret, exit_code = -1;
	int args_size;
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
		if (encode_posix_timer(item, &args->timer[i], temp, &pte[i]))
			goto end_posix;
		tte->posix[i] = &pte[i];
		i++;
	}

	exit_code = 0;
end_posix:
	free_posix_timers(proc_args);
	return exit_code;
}
