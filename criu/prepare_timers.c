#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/shm.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sched.h>


#include "types.h"
#include <compel/ptrace.h>
#include "common/compiler.h"

#include "linux/mount.h"

#include "clone-noasan.h"
#include "cr_options.h"
#include "servicefd.h"
#include "image.h"
#include "img-streamer.h"
#include "util.h"
#include "util-pie.h"
#include "criu-log.h"
#include "restorer.h"
#include "sockets.h"
#include "sk-packet.h"
#include "common/lock.h"
#include "files.h"
#include "pipes.h"
#include "fifo.h"
#include "sk-inet.h"
#include "eventfd.h"
#include "eventpoll.h"
#include "signalfd.h"
#include "proc_parse.h"
#include "pie/restorer-blob.h"
#include "crtools.h"
#include "uffd.h"
#include "namespaces.h"
#include "mem.h"
#include "mount.h"
#include "fsnotify.h"
#include "pstree.h"
#include "net.h"
#include "tty.h"
#include "cpu.h"
#include "file-lock.h"
#include "vdso.h"
#include "stats.h"
#include "tun.h"
#include "vma.h"
#include "kerndat.h"
#include "rst-malloc.h"
#include "plugin.h"
#include "cgroup.h"
#include "timerfd.h"
#include "action-scripts.h"
#include "shmem.h"
#include "aio.h"
#include "lsm.h"
#include "seccomp.h"
#include "fault-injection.h"
#include "sk-queue.h"
#include "sigframe.h"
#include "fdstore.h"
#include "string.h"
#include "memfd.h"
#include "timens.h"
#include "bpfmap.h"

#include "parasite-syscall.h"
#include "files-reg.h"
#include <compel/plugins/std/syscall-codes.h>
#include "compel/include/asm/syscall.h"

#include "protobuf.h"
#include "images/sa.pb-c.h"
#include "images/timer.pb-c.h"
#include "images/vma.pb-c.h"
#include "images/rlimit.pb-c.h"
#include "images/pagemap.pb-c.h"
#include "images/siginfo.pb-c.h"

#include "restore.h"

#include "cr-errno.h"

static int prepare_itimers_from_fd(int pid, struct task_restore_args *args)
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

static int prepare_itimers(int pid, struct task_restore_args *args, CoreEntry *core)
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

static inline int decode_posix_timer(PosixTimerEntry *pte,
		struct restore_posix_timer *pt)
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
		qsort(tmem, ta->posix_timers_n,
				sizeof(struct restore_posix_timer),
				cmp_posix_timer_proc_id);
	}
}

/*
 * Legacy posix timers restoration from CR_FD_POSIX_TIMERS
 */

static int prepare_posix_timers_from_fd(int pid, struct task_restore_args *ta)
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

static int prepare_posix_timers(int pid, struct task_restore_args *ta, CoreEntry *core)
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
