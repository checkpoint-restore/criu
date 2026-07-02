/*
 * CLONE phased dump driver.
 *
 * Implements the WP_ASYNC -> WP_SYNC phased migration flow on the source
 * (dump) side: pre-dump + WP_ASYNC, bulk page transfer + iterative dirty
 * scan, freeze + skeleton dump. Tracks per-process VMA state and handles
 * UFFD UNMAP/REMOVE/REMAP events that arrive while the process runs.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <inttypes.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <poll.h>
#include <time.h>
#include <string.h>

#include "types.h"
#include "cr_options.h"
#include "pstree.h"
#include "clone/clone-dump.h"
#include "mman.h"
#include "uffd.h"
#include "pagemap_scan.h"
#include "page-xfer.h"
#include "parasite-syscall.h"
#include "mem.h"
#include "vma.h"
#include "util.h"
#include "kerndat.h"
#include "criu-log.h"
#include "parasite.h"
#include "seize.h"
#include "clone/clone-conf.h"
#include "clone/clone-bulk-send.h"
#include "clone/clone-page-xfer.h"
#include "common/bug.h"

/* Headers for cr_dump_tasks_clone_phased */
#include "imgset.h"
#include "crtools.h"
#include "dump.h"
#include "net.h"
#include "action-scripts.h"
#include "seccomp.h"
#include "lsm.h"
#include "fdinfo.h"
#include "files.h"
#include "plugin.h"
#include "cgroup.h"
#include "irmap.h"
#include "cr-service.h"
#include "proc_parse.h"
#include "namespaces.h"
#include "page-pipe.h"

#undef LOG_PREFIX
#define LOG_PREFIX "clone-dump: "

struct clone_runtime_cfg clone_cfg;

void clone_cfg_init(int p3_threads, int p3_threads_bulk,
		  int scanners, int pre_scanners, int drain_threads,
		  bool pre_scan)
{
	clone_cfg.num_p3_threads = p3_threads;
	clone_cfg.num_p3_threads_bulk = p3_threads_bulk;
	clone_cfg.num_scanners = scanners;
	clone_cfg.num_pre_scanners = pre_scanners;
	clone_cfg.num_drain_threads = drain_threads;
	clone_cfg.pre_scan = pre_scan;

	pr_info("CLONE config: p3=%d p3_bulk=%d scanners=%d pre_scanners=%d drain=%d pre_scan=%d\n",
		p3_threads, p3_threads_bulk, scanners, pre_scanners, drain_threads, pre_scan);
}

int clone_cfg_init_from_opts(int p3, int p3_bulk, int scan,
			   int pre_scan_threads, int drain, bool pre_scan)
{
	if (!p3)
		p3 = CLONE_DEFAULT_P3_THREADS;
	if (!p3_bulk)
		p3_bulk = CLONE_DEFAULT_P3_THREADS_BULK;
	if (!scan)
		scan = CLONE_DEFAULT_SCANNERS;
	if (!pre_scan_threads)
		pre_scan_threads = CLONE_DEFAULT_PRE_SCANNERS;
	if (!drain)
		drain = CLONE_DEFAULT_DRAIN_THREADS;

	if (p3 > CLONE_MAX_P3_THREADS) {
		pr_err("--clone-p3-threads %d exceeds max %d\n",
		       p3, CLONE_MAX_P3_THREADS);
		return -1;
	}
	if (scan > CLONE_MAX_SCANNERS) {
		pr_err("--clone-scanners %d exceeds max %d\n",
		       scan, CLONE_MAX_SCANNERS);
		return -1;
	}
	if (drain > CLONE_MAX_DRAIN_THREADS) {
		pr_err("--clone-drain-threads %d exceeds max %d\n",
		       drain, CLONE_MAX_DRAIN_THREADS);
		return -1;
	}

	clone_cfg_init(p3, p3_bulk, scan, pre_scan_threads, drain, pre_scan);
	return 0;
}

struct clone_tracked_vma {
	unsigned long start;
	unsigned long end;
};

/*
 * Track ranges that were unmapped during Phase 2 (detected via UFFD events
 * or EFAULT from process_vm_readv). Phase 3 checks if new VMAs appeared
 * at these addresses to detect munmap+mmap remaps.
 */
struct clone_unmapped_range {
	unsigned long start;
	unsigned long end;
};

/* CLONE dump state for one dump session — single tracked process */
struct clone_dump_info {
	pid_t source_pid;
	u64 dst_id;            /* Process identifier for page transfer */
	int uffd;              /* WP_ASYNC uffd fd */
	unsigned int nr_tracked_vmas;
	struct clone_tracked_vma *tracked_vmas;
	enum clone_dump_phase phase;  /* Current phase */

	/* Unmapped ranges detected via UFFD events or EFAULT during Phase 2 */
	struct clone_unmapped_range *unmapped_ranges;
	unsigned int nr_unmapped_ranges;
	unsigned int unmapped_capacity;
	pthread_mutex_t unmapped_lock;

	/* Event reader thread state */
	pthread_t event_reader_thread;
	atomic_int phase3_started;
	bool event_reader_running;
};

/*
 * Applying UFFD write-protect over a large address space can dominate the
 * initial stall.  We apply it in parallel from the CRIU process.
 * CLONE_WP_CHUNK_SIZE is now defined in clone-conf.h
 */

struct clone_wp_range {
	unsigned long start;
	unsigned long len;
};

struct clone_wp_job {
	int uffd;
	struct clone_wp_range *ranges;
	unsigned int start_idx;
	unsigned int end_idx;
	int err;
};

static void *clone_wp_worker(void *arg)
{
	struct clone_wp_job *job = arg;
	struct uffdio_writeprotect wp;
	unsigned int i;

	for (i = job->start_idx; i < job->end_idx; i++) {
		wp.range.start = job->ranges[i].start;
		wp.range.len = job->ranges[i].len;
		wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;

		if (ioctl(job->uffd, UFFDIO_WRITEPROTECT, &wp)) {
			job->err = -errno;
			return NULL;
		}
	}

	return NULL;
}

static unsigned int clone_wp_nr_threads(unsigned int nr_ranges)
{
	long nproc;
	unsigned int nr_threads;

	nproc = sysconf(_SC_NPROCESSORS_ONLN);
	if (nproc < 1)
		return 1;

	nr_threads = (unsigned int)nproc;
	if (nr_threads > nr_ranges)
		nr_threads = nr_ranges;
	if (nr_threads < 1)
		nr_threads = 1;

	return nr_threads;
}

static struct clone_wp_range *clone_wp_build_ranges(struct clone_dump_info *cdi,
						unsigned int *nr_ranges)
{
	struct clone_wp_range *ranges;
	unsigned long start, end, pos, len;
	unsigned int nr = 0, i, idx = 0;

	for (i = 0; i < cdi->nr_tracked_vmas; i++) {
		start = cdi->tracked_vmas[i].start;
		end = cdi->tracked_vmas[i].end;
		if (end <= start)
			continue;
		len = end - start;
		nr += (len + CLONE_WP_CHUNK_SIZE - 1) / CLONE_WP_CHUNK_SIZE;
	}

	if (nr == 0) {
		*nr_ranges = 0;
		return NULL;
	}

	*nr_ranges = nr;
	ranges = xmalloc(nr * sizeof(*ranges));
	BUG_ON(!ranges);

	for (i = 0; i < cdi->nr_tracked_vmas; i++) {
		start = cdi->tracked_vmas[i].start;
		end = cdi->tracked_vmas[i].end;
		if (end <= start)
			continue;
		pos = start;
		while (pos < end) {
			len = end - pos;
			if (len > CLONE_WP_CHUNK_SIZE)
				len = CLONE_WP_CHUNK_SIZE;
			ranges[idx].start = pos;
			ranges[idx].len = len;
			idx++;
			pos += len;
		}
	}

	*nr_ranges = idx;
	return ranges;
}

static int clone_apply_writeprotect(struct clone_dump_info *cdi)
{
	struct clone_wp_range *ranges;
	struct clone_wp_job *jobs;
	pthread_t *threads;
	struct timespec t_start, t_end;
	unsigned int nr_ranges, nr_threads, i, created = 0, per;
	unsigned long sec, nsec;
	int ret = 0;

	if (!cdi->nr_tracked_vmas)
		return 0;

	ranges = clone_wp_build_ranges(cdi, &nr_ranges);
	if (!ranges) {
		/* nr_ranges == 0 means no VMAs to protect, which is fine */
		BUG_ON(nr_ranges != 0);
		return 0;
	}

	nr_threads = clone_wp_nr_threads(nr_ranges);
	threads = xmalloc(nr_threads * sizeof(*threads));
	jobs = xzalloc(nr_threads * sizeof(*jobs));
	BUG_ON(!threads || !jobs);

	per = (nr_ranges + nr_threads - 1) / nr_threads;
	for (i = 0; i < nr_threads; i++) {
		jobs[i].uffd = cdi->uffd;
		jobs[i].ranges = ranges;
		jobs[i].start_idx = i * per;
		jobs[i].end_idx = jobs[i].start_idx + per;
		if (jobs[i].end_idx > nr_ranges)
			jobs[i].end_idx = nr_ranges;
	}

	clock_gettime(CLOCK_MONOTONIC, &t_start);

	for (i = 0; i < nr_threads; i++) {
		if (jobs[i].start_idx >= jobs[i].end_idx)
			break;
		if (pthread_create(&threads[i], NULL, clone_wp_worker, &jobs[i])) {
			pr_err("Failed to create write-protect worker thread\n");
			ret = -1;
			break;
		}
		created++;
	}

	for (i = 0; i < created; i++)
		pthread_join(threads[i], NULL);

	clock_gettime(CLOCK_MONOTONIC, &t_end);

	for (i = 0; i < created; i++) {
		if (jobs[i].err) {
			pr_err("Failed to apply UFFD write-protect: %s (%d)\n",
			       strerror(-jobs[i].err), -jobs[i].err);
			ret = -1;
			break;
		}
	}

	sec = t_end.tv_sec - t_start.tv_sec;
	if (t_end.tv_nsec < t_start.tv_nsec) {
		sec--;
		nsec = 1000000000UL + t_end.tv_nsec - t_start.tv_nsec;
	} else {
		nsec = t_end.tv_nsec - t_start.tv_nsec;
	}
	pr_debug("clone_dump_writeprotect took %lu.%06lu seconds (%u ranges, %u threads)\n",
		 sec, nsec / 1000, nr_ranges, created ? created : 1);

	xfree(threads);
	xfree(jobs);
	xfree(ranges);
	return ret;
}

/* ------------------------------------------------------------------ */
/*  Global state                                                       */
/* ------------------------------------------------------------------ */

static struct clone_dump_info *g_clone_info = NULL;

/*
 * clone_set_dst_id - Update the dst_id after collect_pstree_ids() populates vpid
 *
 * In CLONE phased dump, g_clone_info is initialized in Phase 1 before
 * collect_pstree_ids() runs, so vpid(item) returns -1 at that time.
 * This function allows cr-dump.c to update dst_id in Phase 3 after
 * the IDs are properly collected.
 */
void clone_set_dst_id(u64 dst_id)
{
	if (g_clone_info)
		g_clone_info->dst_id = dst_id;
}

/* ------------------------------------------------------------------ */
/*  VMA registration                                                   */
/* ------------------------------------------------------------------ */

/*
 * clone_register_vmas - Build list of VMAs to track for CLONE
 *
 * In WP_ASYNC mode, we don't actually register with uffd for WP faults.
 * Instead, we just build the list of trackable VMAs and use PAGEMAP_SCAN
 * to detect dirty pages later.
 */
static int clone_register_vmas(struct clone_dump_info *cdi,
			     struct vm_area_list *vma_area_list,
			     unsigned long *out_total_pages)
{
	struct vma_area *vma;
	struct uffdio_register reg;
	unsigned int nr_eligible = 0, nr_tracked = 0;
	unsigned long total_pages = 0;
	struct clone_tracked_vma *tvmas;
	unsigned int i;

	list_for_each_entry(vma, &vma_area_list->h, list) {
		if (!vma_entry_can_be_lazy(vma->e))
			continue;
		if (vma_area_is(vma, VMA_AREA_GUARD))
			continue;
		if (!(vma->e->prot & PROT_WRITE))
			continue;
		if (!vma_area_is_private(vma, kdat.task_size) &&
		    !vma_area_is(vma, VMA_ANON_SHARED))
			continue;
		if (vma_entry_is(vma->e, VMA_AREA_VVAR))
			continue;
		if (vma->e->flags & MAP_DROPPABLE)
			continue;
		nr_eligible++;
	}

	if (!nr_eligible) {
		*out_total_pages = 0;
		return 0;
	}

	tvmas = xzalloc(sizeof(*tvmas) * nr_eligible);
	BUG_ON(!tvmas);

	i = 0;
	list_for_each_entry(vma, &vma_area_list->h, list) {
		unsigned long start = vma->e->start;
		unsigned long len = vma->e->end - start;
		const char *skip_reason = NULL;
		int ioctl_ret;

		if (!vma_entry_can_be_lazy(vma->e))
			skip_reason = "can_be_lazy";
		else if (vma_area_is(vma, VMA_AREA_GUARD))
			skip_reason = "guard";
		else if (!(vma->e->prot & PROT_WRITE))
			skip_reason = "not_writable";
		else if (!vma_area_is_private(vma, kdat.task_size) &&
			 !vma_area_is(vma, VMA_ANON_SHARED))
			skip_reason = "not_private";
		else if (vma_entry_is(vma->e, VMA_AREA_VVAR))
			skip_reason = "vvar";
		else if (vma->e->flags & MAP_DROPPABLE)
			skip_reason = "droppable";

		if (skip_reason) {
			pr_debug("VMA_TRACE: phase=WP_REGISTER vma=0x%lx-0x%lx flags=0x%x prot=0x%x status=0x%x shmid=%" PRIu64
			       " skipped_by=%s\n",
			       start, start + len,
			       vma->e->flags, vma->e->prot, vma->e->status,
			       (uint64_t)vma->e->shmid, skip_reason);
			continue;
		}

		/*
		 * In WP_ASYNC mode, UFFDIO_REGISTER may fail - that's OK.
		 * We track via PAGEMAP_SCAN, not fault handling.
		 */
		reg.range.start = start;
		reg.range.len = len;
		reg.mode = UFFDIO_REGISTER_MODE_WP;
		ioctl_ret = ioctl(cdi->uffd, UFFDIO_REGISTER, &reg);

		pr_debug("VMA_TRACE: phase=WP_REGISTER vma=0x%lx-0x%lx flags=0x%x prot=0x%x status=0x%x shmid=%" PRIu64
		       " registered ioctl_ret=%d errno=%d pages=%lu\n",
		       start, start + len,
		       vma->e->flags, vma->e->prot, vma->e->status,
		       (uint64_t)vma->e->shmid,
		       ioctl_ret, ioctl_ret < 0 ? errno : 0, len / PAGE_SIZE);

		tvmas[i].start = start;
		tvmas[i].end = start + len;
		total_pages += len / PAGE_SIZE;
		i++;
	}

	nr_tracked = i;
	if (nr_tracked > 0) {
		void *tmp = xrealloc(tvmas, sizeof(*tvmas) * nr_tracked);
		if (tmp)
			tvmas = tmp;
		cdi->tracked_vmas = tvmas;
	} else {
		xfree(tvmas);
		cdi->tracked_vmas = NULL;
	}
	cdi->nr_tracked_vmas = nr_tracked;
	*out_total_pages = total_pages;

	pr_info("Tracking %u/%u VMAs for CLONE: %lu pages\n",
		nr_tracked, nr_eligible, total_pages);
	return 0;
}

/* ------------------------------------------------------------------ */
/*  Init / Fini                                                        */
/* ------------------------------------------------------------------ */

void clone_dump_fini(void)
{
	if (!g_clone_info)
		return;

	/* Stop event reader thread if running */
	if (g_clone_info->event_reader_running) {
		atomic_store(&g_clone_info->phase3_started, 1);
		pthread_join(g_clone_info->event_reader_thread, NULL);
		g_clone_info->event_reader_running = false;
	}

	wait_for_page_server_thread();
	pr_info("Cleaning up CLONE dump\n");

	if (g_clone_info->uffd >= 0)
		close(g_clone_info->uffd);
	xfree(g_clone_info->tracked_vmas);
	xfree(g_clone_info->unmapped_ranges);
	pthread_mutex_destroy(&g_clone_info->unmapped_lock);
	xfree(g_clone_info);
	g_clone_info = NULL;
}

/* ------------------------------------------------------------------ */
/*  Unmapped range tracking (UFFD events + EFAULT fallback)            */
/* ------------------------------------------------------------------ */

/*
 * clone_record_unmapped_range - Record a range that was unmapped during Phase 2
 *
 * Called from:
 * - UFFD event reader thread when UFFD_EVENT_UNMAP/REMOVE is received
 * - Bulk sender when process_vm_readv returns EFAULT
 *
 * Thread-safe: multiple callers may run in parallel.
 */
void clone_record_unmapped_range(unsigned long start, unsigned long len)
{
	struct clone_dump_info *cdi = g_clone_info;

	if (!cdi)
		return;

	pthread_mutex_lock(&cdi->unmapped_lock);

	if (cdi->nr_unmapped_ranges >= cdi->unmapped_capacity) {
		unsigned int new_cap = cdi->unmapped_capacity ?
				       cdi->unmapped_capacity * 2 : 16;
		/* xrealloc() returns NULL on failure without freeing; use a temp. */
		void *grown = xrealloc(cdi->unmapped_ranges,
				       new_cap * sizeof(*cdi->unmapped_ranges));
		BUG_ON(!grown);
		cdi->unmapped_ranges = grown;
		cdi->unmapped_capacity = new_cap;
	}

	cdi->unmapped_ranges[cdi->nr_unmapped_ranges].start = start;
	cdi->unmapped_ranges[cdi->nr_unmapped_ranges].end = start + len;
	cdi->nr_unmapped_ranges++;

	pr_debug("Recorded unmapped range: 0x%lx-0x%lx\n", start, start + len);

	pthread_mutex_unlock(&cdi->unmapped_lock);
}

/*
 * clone_uffd_event_reader - Background thread to read UFFD events during Phase 2
 *
 * Reads UFFD_EVENT_UNMAP and UFFD_EVENT_REMOVE events, recording unmapped
 * ranges. Thread exits when Phase 3 starts (phase3_started flag set).
 */
static void *clone_uffd_event_reader(void *arg)
{
	struct clone_dump_info *cdi = arg;
	struct uffd_msg msg;
	ssize_t n;

	pr_info("UFFD event reader thread started\n");

	while (!atomic_load(&cdi->phase3_started)) {
		struct pollfd pfd = { .fd = cdi->uffd, .events = POLLIN };
		int ret = poll(&pfd, 1, 100 /* ms */);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			pr_perror("UFFD event reader poll failed");
			break;
		}

		if (ret == 0)
			continue;

		n = read(cdi->uffd, &msg, sizeof(msg));
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			pr_perror("UFFD event reader read failed");
			break;
		}

		if (n != sizeof(msg)) {
			pr_warn("UFFD event reader: short read %zd\n", n);
			continue;
		}

		if (msg.event == UFFD_EVENT_UNMAP ||
		    msg.event == UFFD_EVENT_REMOVE) {
			unsigned long start = msg.arg.remove.start;
			unsigned long end = msg.arg.remove.end;

			pr_debug("UFFD event: %s 0x%lx-0x%lx\n",
				 msg.event == UFFD_EVENT_UNMAP ? "UNMAP" : "REMOVE",
				 start, end);

			clone_record_unmapped_range(start, end - start);
		} else if (msg.event == UFFD_EVENT_REMAP) {
			unsigned long from = msg.arg.remap.from;
			unsigned long to = msg.arg.remap.to;
			unsigned long len = msg.arg.remap.len;

			pr_debug("UFFD event: REMAP 0x%lx -> 0x%lx (len=0x%lx)\n",
				 from, to, len);

			clone_record_unmapped_range(from, len);
		}
	}

	pr_info("UFFD event reader thread exiting\n");
	return NULL;
}

static int clone_start_event_reader(struct clone_dump_info *cdi)
{
	int ret;

	atomic_store(&cdi->phase3_started, 0);

	ret = pthread_create(&cdi->event_reader_thread, NULL,
			     clone_uffd_event_reader, cdi);
	if (ret) {
		pr_err("Failed to create UFFD event reader thread: %d\n", ret);
		return -1;
	}

	cdi->event_reader_running = true;
	return 0;
}

static void clone_stop_event_reader(struct clone_dump_info *cdi)
{
	if (!cdi->event_reader_running)
		return;

	atomic_store(&cdi->phase3_started, 1);
	pthread_join(cdi->event_reader_thread, NULL);
	cdi->event_reader_running = false;

	pr_info("Stopped UFFD event reader, recorded %u unmapped ranges\n",
		cdi->nr_unmapped_ranges);
}

/* ------------------------------------------------------------------ */
/*  Public query API                                                   */
/* ------------------------------------------------------------------ */

bool clone_dump_is_vma_tracked(pid_t source_pid, unsigned long start,
			     unsigned long end)
{
	unsigned int i;

	if (!g_clone_info || g_clone_info->source_pid != source_pid)
		return false;

	for (i = 0; i < g_clone_info->nr_tracked_vmas; i++) {
		if (g_clone_info->tracked_vmas[i].start == start &&
		    g_clone_info->tracked_vmas[i].end == end)
			return true;
	}

	return false;
}


/* ------------------------------------------------------------------ */
/*  Phase management                                                   */
/* ------------------------------------------------------------------ */

enum clone_dump_phase clone_get_phase(void)
{
	if (!g_clone_info)
		return CLONE_PHASE_IDLE;
	return g_clone_info->phase;
}

void clone_set_phase(enum clone_dump_phase phase)
{
	if (g_clone_info)
		g_clone_info->phase = phase;
}

bool clone_is_phased_skeleton_dump(void)
{
	/*
	 * In CLONE phased migration, Phase 3 (SCAN) dumps everything except
	 * memory pages. This is detected by checking:
	 * 1. CLONE dump mode is enabled (which implies the lazy-pages transport)
	 * 2. We're at or past the SCAN phase (pages already sent in Phase 2)
	 */
	if (!opts.clone_dump)
		return false;
	if (!g_clone_info)
		return false;
	return g_clone_info->phase >= CLONE_PHASE_SCAN;
}

/* ------------------------------------------------------------------ */
/*  WP_ASYNC phased migration support                                  */
/* ------------------------------------------------------------------ */

int clone_dump_init_async(struct pstree_item *item,
			struct vm_area_list *vma_area_list,
			struct parasite_ctl *ctl)
{
	struct clone_dump_info *cdi;
	struct parasite_clone_dump_args *args = NULL;
	unsigned long args_size;
	unsigned long total_pages;
	int ret;

	pr_info("Initializing CLONE dump ASYNC for pid %d\n", item->pid->real);

	if (g_clone_info) {
		pr_warn("CLONE tracking already initialized\n");
		return 0;
	}

	cdi = xzalloc(sizeof(*cdi));
	BUG_ON(!cdi);

	cdi->source_pid = item->pid->real;
	cdi->dst_id = vpid(item);
	cdi->uffd = -1;
	cdi->phase = CLONE_PHASE_ASYNC_BULK;
	pthread_mutex_init(&cdi->unmapped_lock, NULL);
	atomic_store(&cdi->phase3_started, 0);

	g_clone_info = cdi;

	/*
	 * Create UFFD with WP_ASYNC via the parasite running inside
	 * the target process.  This avoids /proc/<pid>/userfaultfd
	 * which is deprecated / missing on some kernels.
	 */
	if (!ctl) {
		pr_err("Parasite control required for WP_ASYNC uffd creation\n");
		goto err;
	}

	args_size = sizeof(*args);
	args = compel_parasite_args_s(ctl, args_size);
	if (!args) {
		pr_err("Failed to allocate parasite args for WP_ASYNC\n");
		goto err;
	}

	args->nr_vmas = 0;
	args->total_pages = 0;
	args->nr_failed_vmas = 0;
	args->uffd_features = UFFD_FEATURE_WP_ASYNC |
			      UFFD_FEATURE_EVENT_UNMAP |
			      UFFD_FEATURE_EVENT_REMOVE |
			      UFFD_FEATURE_EVENT_REMAP |
			      UFFD_FEATURE_WP_UNPOPULATED;
	args->ret = -1;

	ret = compel_rpc_call(PARASITE_CMD_CLONE_DUMP_INIT, ctl);
	if (ret < 0) {
		pr_err("Failed to initiate CLONE dump ASYNC RPC\n");
		goto err;
	}

	compel_util_recv_fd(ctl, &cdi->uffd);
	if (cdi->uffd < 0) {
		pr_err("Failed to receive WP_ASYNC uffd from parasite: %d\n",
		       cdi->uffd);
		goto err;
	}

	ret = compel_rpc_sync(PARASITE_CMD_CLONE_DUMP_INIT, ctl);
	if (ret < 0 || args->ret != 0) {
		pr_err("Parasite CLONE dump ASYNC init failed: %d (ret=%d)\n",
		       ret, args->ret);
		goto err;
	}

	/* Build list of VMAs to track */
	ret = clone_register_vmas(cdi, vma_area_list, &total_pages);
	if (ret)
		goto err;

	/* Apply write-protect */
	if (clone_apply_writeprotect(cdi))
		goto err;

	/* Start UFFD event reader thread to track unmaps during Phase 2 */
	if (clone_start_event_reader(cdi))
		goto err;

	pr_info("CLONE ASYNC initialized for pid %d: tracked=%u pages=%lu uffd=%d\n",
		item->pid->real, cdi->nr_tracked_vmas, total_pages, cdi->uffd);
	return 0;

err:
	if (cdi->uffd >= 0)
		close(cdi->uffd);
	xfree(cdi->tracked_vmas);
	xfree(cdi);
	g_clone_info = NULL;
	return -1;
}

/*
 * clone_is_vma_trackable - Check if a VMA should be CLONE-tracked
 *
 * Uses the same criteria as clone_register_vmas() to determine if a VMA
 * is eligible for CLONE tracking.
 */
static bool clone_is_vma_trackable(struct vma_area *vma)
{
	if (!vma_entry_can_be_lazy(vma->e))
		return false;
	if (vma_area_is(vma, VMA_AREA_GUARD))
		return false;
	if (!(vma->e->prot & PROT_WRITE))
		return false;
	if (!vma_area_is_private(vma, kdat.task_size) &&
	    !vma_area_is(vma, VMA_ANON_SHARED))
		return false;
	if (vma_entry_is(vma->e, VMA_AREA_VVAR))
		return false;
	if (vma->e->flags & MAP_DROPPABLE)
		return false;
	return true;
}

/*
 * clone_region_subtract - Subtract tracked region from [start, end)
 *
 * Returns the portion(s) of [start, end) not covered by the tracked VMAs.
 * Appends results to ranges array at *nr_ranges position.
 */
static int clone_region_subtract(unsigned long start, unsigned long end,
			       unsigned long **ranges, unsigned int *nr_ranges,
			       unsigned int *capacity)
{
	struct clone_dump_info *cdi = g_clone_info;
	unsigned int i;
	unsigned long cur_start = start;

	if (!cdi || !cdi->nr_tracked_vmas) {
		/* No tracked VMAs, entire region is new */
		goto add_region;
	}

	/*
	 * Walk through tracked VMAs and find gaps.
	 * tracked_vmas are sorted by start address from clone_register_vmas.
	 */
	for (i = 0; i < cdi->nr_tracked_vmas && cur_start < end; i++) {
		unsigned long t_start = cdi->tracked_vmas[i].start;
		unsigned long t_end = cdi->tracked_vmas[i].end;

		/* Skip tracked VMAs that end before our current position */
		if (t_end <= cur_start)
			continue;

		/* Skip tracked VMAs that start after our region ends */
		if (t_start >= end)
			break;

		/* Found overlap - add the gap before this tracked VMA */
		if (t_start > cur_start) {
			unsigned long gap_end = (t_start < end) ? t_start : end;
			unsigned long gap_len = gap_end - cur_start;

			if (*nr_ranges >= *capacity) {
				unsigned int new_cap = *capacity ? *capacity * 2 : 64;
				unsigned long *new_ranges;

				new_ranges = xrealloc(*ranges,
						      new_cap * 2 * sizeof(unsigned long));
				BUG_ON(!new_ranges);
				*ranges = new_ranges;
				*capacity = new_cap;
			}

			(*ranges)[(*nr_ranges) * 2] = cur_start;
			(*ranges)[(*nr_ranges) * 2 + 1] = gap_len;
			(*nr_ranges)++;

			pr_debug("  new region: 0x%lx-0x%lx (%lu pages)\n",
				cur_start, gap_end, gap_len / PAGE_SIZE);
		}

		/* Move past this tracked VMA */
		cur_start = t_end;
	}

add_region:
	/* Add any remaining portion after all tracked VMAs */
	if (cur_start < end) {
		unsigned long len = end - cur_start;

		if (*nr_ranges >= *capacity) {
			unsigned int new_cap = *capacity ? *capacity * 2 : 64;
			unsigned long *new_ranges;

			new_ranges = xrealloc(*ranges,
					      new_cap * 2 * sizeof(unsigned long));
			BUG_ON(!new_ranges);
			*ranges = new_ranges;
			*capacity = new_cap;
		}

		(*ranges)[(*nr_ranges) * 2] = cur_start;
		(*ranges)[(*nr_ranges) * 2 + 1] = len;
		(*nr_ranges)++;

		pr_info("  new region: 0x%lx-0x%lx (%lu pages)\n",
			cur_start, end, len / PAGE_SIZE);
	}

	return 0;
}

/*
 * clone_extend_tracked_vmas - Add new regions to tracked_vmas array
 *
 * Extends g_clone_info->tracked_vmas to include new VMA regions discovered
 * in Phase 3. This ensures the fault handler can find these regions during
 * WP_SYNC convergence.
 *
 * Also adds these regions to global_lazy_vmas so the page server can
 * iterate through them during page transfer.
 *
 * @ranges: Array of [start, len, ...] pairs
 * @nr_ranges: Number of ranges
 *
 * Returns: 0 on success, -1 on error
 */
static int clone_extend_tracked_vmas(unsigned long *ranges, unsigned int nr_ranges)
{
	struct clone_dump_info *cdi = g_clone_info;
	struct clone_tracked_vma *new_tracked;
	unsigned int new_total;
	unsigned int i;

	if (!cdi || nr_ranges == 0)
		return 0;

	new_total = cdi->nr_tracked_vmas + nr_ranges;
	new_tracked = xrealloc(cdi->tracked_vmas,
			       new_total * sizeof(*new_tracked));
	BUG_ON(!new_tracked);

	/* Update pointer immediately - xrealloc may have moved the buffer */
	cdi->tracked_vmas = new_tracked;

	/* Append new regions (ranges are [start, len] pairs) */
	for (i = 0; i < nr_ranges; i++) {
		unsigned long start = ranges[i * 2];
		unsigned long len = ranges[i * 2 + 1];

		new_tracked[cdi->nr_tracked_vmas + i].start = start;
		new_tracked[cdi->nr_tracked_vmas + i].end = start + len;
		pr_debug("Added new tracked VMA: 0x%lx-0x%lx\n", start, start + len);

		/* Also add to lazy VMA list for page transfer */
		if (clone_mem_add_lazy_vma_range(start, len,
						 cdi->dst_id, cdi->source_pid)) {
			pr_err("Failed to add lazy VMA for 0x%lx-0x%lx\n",
			       start, start + len);
			BUG();
		}
	}

	cdi->nr_tracked_vmas = new_total;
	pr_info("Extended tracked_vmas: now %u total\n", new_total);

	return 0;
}

/*
 * clone_detect_new_vmas - Detect VMAs that appeared after Phase 1
 *
 * Compares the current VMA list with the tracked VMAs from Phase 1.
 * Returns ranges for any new or extended VMA regions that weren't
 * tracked. These regions need to be marked dirty for WP_SYNC since
 * we have no record of their pages from Phase 2.
 *
 * Also updates g_clone_info->tracked_vmas to include the new regions
 * so the fault handler can find them during convergence.
 *
 * @vmas: Current VMA list (from collect_mappings in Phase 3)
 * @new_ranges: Output array of [start, len, ...] pairs
 * @nr_new_ranges: Output count of new ranges
 *
 * Caller must xfree() the new_ranges array.
 * Returns: 0 on success, -1 on error
 */
int clone_detect_new_vmas(struct vm_area_list *vmas,
			unsigned long **new_ranges,
			unsigned int *nr_new_ranges)
{
	struct vma_area *vma;
	unsigned long *ranges = NULL;
	unsigned int nr_ranges = 0;
	unsigned int capacity = 0;
	unsigned int i;
	struct clone_dump_info *cdi = g_clone_info;

	if (!cdi) {
		pr_err("CLONE dump not initialized\n");
		return -1;
	}

	/* Stop UFFD event reader - Phase 3 begins, process is frozen */
	clone_stop_event_reader(cdi);

	*new_ranges = NULL;
	*nr_new_ranges = 0;

	pr_info("Detecting new VMAs (comparing against %u tracked VMAs)\n",
		cdi->nr_tracked_vmas);

	list_for_each_entry(vma, &vmas->h, list) {
		unsigned long start = vma->e->start;
		unsigned long end = vma->e->end;
		unsigned int before;

		/* Use same filtering as clone_register_vmas */
		if (!clone_is_vma_trackable(vma)) {
			pr_debug("VMA_TRACE: phase=PHASE3_NEW_VMA_DETECT vma=0x%lx-0x%lx flags=0x%x prot=0x%x status=0x%x shmid=%" PRIu64
			       " trackable=0 skipped\n",
			       start, end,
			       vma->e->flags, vma->e->prot, vma->e->status,
			       (uint64_t)vma->e->shmid);
			continue;
		}

		pr_debug("Checking VMA 0x%lx-0x%lx\n", start, end);

		before = nr_ranges;
		if (clone_region_subtract(start, end, &ranges, &nr_ranges, &capacity)) {
			xfree(ranges);
			return -1;
		}
		pr_debug("VMA_TRACE: phase=PHASE3_NEW_VMA_DETECT vma=0x%lx-0x%lx flags=0x%x prot=0x%x status=0x%x shmid=%" PRIu64
		       " trackable=1 new_ranges_emitted=%u\n",
		       start, end,
		       vma->e->flags, vma->e->prot, vma->e->status,
		       (uint64_t)vma->e->shmid,
		       nr_ranges - before);
	}

	/*
	 * Second pass: check unmapped ranges recorded during Phase 2.
	 *
	 * UFFD_EVENT_UNMAP/REMOVE events and EFAULT from process_vm_readv
	 * recorded ranges that were unmapped while the process was running.
	 * If a VMA now exists at that address, it was remapped (munmap+mmap).
	 * We must treat it as "new" to trigger full content resend.
	 *
	 * This catches the case where:
	 * 1. Phase 1: VMA at [A, A+size) tracked
	 * 2. Phase 2: Process does munmap([A, A+size)) - event/EFAULT recorded
	 * 3. Phase 2: Process does mmap(MAP_FIXED, [A, A+size)) - new VMA
	 * 4. Phase 3: clone_region_subtract() sees VMA - no gap detected!
	 * 5. Without this check: zero-fill pages never sent → SIGBUS
	 */
	pr_info("CLONE REMAP CHECK: checking %u unmapped ranges for remap\n",
		cdi->nr_unmapped_ranges);
	for (i = 0; i < cdi->nr_unmapped_ranges; i++) {
		unsigned long u_start = cdi->unmapped_ranges[i].start;
		unsigned long u_end = cdi->unmapped_ranges[i].end;
		bool has_new_vma = false;

		/* Check if any current VMA overlaps this unmapped range */
		list_for_each_entry(vma, &vmas->h, list) {
			if (!clone_is_vma_trackable(vma))
				continue;
			if (vma->e->start < u_end && vma->e->end > u_start) {
				has_new_vma = true;
				break;
			}
		}

		if (has_new_vma) {
			unsigned long len = u_end - u_start;

			if (nr_ranges >= capacity) {
				unsigned int new_cap = capacity ? capacity * 2 : 64;
				unsigned long *new_r;

				new_r = xrealloc(ranges,
						 new_cap * 2 * sizeof(unsigned long));
				BUG_ON(!new_r);
				ranges = new_r;
				capacity = new_cap;
			}

			ranges[nr_ranges * 2] = u_start;
			ranges[nr_ranges * 2 + 1] = len;
			nr_ranges++;

			pr_debug("CLONE REMAP: 0x%lx-0x%lx was unmapped then new VMA "
			       "appeared - treating as new for full resend\n",
			       u_start, u_end);
		} else {
			pr_debug("CLONE UNMAP: 0x%lx-0x%lx was unmapped, no new VMA - "
				 "truly unmapped\n", u_start, u_end);
			/*
			 * Pages from a region the source unmapped (without
			 * remapping) are still present on the target as part
			 * of the Phase-1 VMA. The pages are released via
			 * MADV_DONTNEED on the target; the VMA itself is left
			 * intact.
			 */
		}
	}

	*new_ranges = ranges;
	*nr_new_ranges = nr_ranges;

	pr_debug("CLONE NEW VMAs: Detected %u new VMA regions since Phase 1\n", nr_ranges);

	/* Log details of each new VMA range */
	if (nr_ranges > 0) {
		unsigned int i;
		pr_warn("New VMAs created on the source after Phase 1 dump:\n");
		for (i = 0; i < nr_ranges; i++) {
			unsigned long start = ranges[i * 2];
			unsigned long len = ranges[i * 2 + 1];
			pr_debug("  new VMA [%u]: 0x%lx-0x%lx (size=%luKB)\n",
			       i, start, start + len, len / 1024);
		}
		pr_warn("These VMAs will not exist on the target (metadata not re-dumped after Phase 1)\n");
	}

	/* Extend tracked_vmas so fault handler can find new regions */
	if (clone_extend_tracked_vmas(ranges, nr_ranges))
		return -1;

	return 0;
}

/**
 * clone_cleanup_async_uffd - Close async uffd without unregistering VMAs
 *
 * The kernel automatically cleans up uffd registrations when the fd is closed.
 * This avoids the expensive UFFDIO_UNREGISTER page walks that can take minutes
 * on large memory systems.
 */
void clone_cleanup_async_uffd(void)
{
	struct clone_dump_info *cdi = g_clone_info;
	struct uffdio_range range;
	unsigned int i;
	int ret;

	if (!cdi)
		return;

	/*
	 * Unregister VMAs in chunks with yields between each.
	 * This spreads the kernel page-table walk time and allows
	 * the target process to make progress between chunks.
	 */
	if (cdi->uffd >= 0 && cdi->tracked_vmas && cdi->nr_tracked_vmas > 0) {
		pr_info("Unregistering %u VMAs from uffd fd=%d (chunked)\n",
			cdi->nr_tracked_vmas, cdi->uffd);

		for (i = 0; i < cdi->nr_tracked_vmas; i++) {
			range.start = cdi->tracked_vmas[i].start;
			range.len = cdi->tracked_vmas[i].end - cdi->tracked_vmas[i].start;

			ret = ioctl(cdi->uffd, UFFDIO_UNREGISTER, &range);
			if (ret < 0 && errno != EINVAL) {
				/* EINVAL = already unregistered, ignore */
				pr_debug("UFFDIO_UNREGISTER %lx-%lx failed: %s\n",
					 (unsigned long)range.start,
					 (unsigned long)(range.start + range.len),
					 strerror(errno));
			}

			/* Yield to let target process run between chunks */
			if ((i + 1) % (CLONE_UFFD_UNREGISTER_YIELD +
				       cdi->nr_tracked_vmas / CLONE_UFFD_YIELD_VMA_DIVISOR) == 0)
				usleep(CLONE_USLEEP_10MS);
		}
	}

	if (cdi->uffd >= 0) {
		pr_debug("Closing uffd fd=%d\n", cdi->uffd);
		close(cdi->uffd);
		cdi->uffd = -1;
	}

}

/*
 * cr_dump_clone_finish - Clone-specific finish operations
 *
 * Handles signaling the target, optional comparison, unfreezing the
 * process, and cleanup. Called from cr_dump_finish() when clone dump is
 * complete.
 *
 * @ret: current return status (0 = success so far)
 * Returns: updated return status
 */
int cr_dump_clone_finish(int ret)
{
	int sk = get_page_server_sk();

	pr_debug("Signaling target (ret=%d, sk=%d)\n", ret, sk);

	/*
	 * Send single completion signal while frozen (fast).
	 * Target waits for this before starting restore.
	 */
	if (!ret && sk >= 0) {
		if (clone_send_skeleton_files(sk) < 0) {
			pr_err("Failed to send skeleton files\n");
			ret = -1;
		}
		if (!ret && send_all_pages_sent_signal(sk) < 0) {
			pr_err("Failed to send completion signal\n");
			ret = -1;
		}
	}

	pr_debug("Unfreezing process\n");
	pstree_switch_state(root_item, TASK_ALIVE);
	/* Wait for ACK AFTER unfreeze - not on critical path */
	if (!ret && sk >= 0) {
		if (wait_for_all_pages_sent_ack(sk) < 0) {
			pr_err("Failed to receive completion ACK\n");
			ret = -1;
		}
	}

	/* Cleanup after unfreeze - not on critical path */
	clone_cleanup_async_uffd();

	/* Close page server socket AFTER unfreeze */
	clone_close_page_server_socket();

	return ret;
}

/*
 * cr_dump_tasks_clone_phased - CLONE phased migration orchestration
 *
 * Implements the WP_ASYNC → WP_SYNC phased migration flow:
 *   Phase 1: pre_dump → WP_ASYNC all VMAs → resume immediately
 *   Phase 2: bulk page transfer (process running, writes tracked async)
 *   Phase 3: freeze → dump skeleton (no pages) → PAGEMAP_SCAN dirty pages
 *   Phase 4: WP_SYNC on dirty pages → resume → convergence
 */
int cr_dump_tasks_clone_phased(pid_t pid)
{
	InventoryEntry he = INVENTORY_ENTRY__INIT;
	InventoryEntry *parent_ie = NULL;
	struct pstree_item *item;
	int ret;
	int exit_code = -1;

	if (cr_dump_init(pid, &he, "CLONE Phased dump"))
		goto err;

	/* Phase 1: seize + pre-dump + WP_ASYNC */
	pr_debug("PHASE 1: Seize + Pre-dump + WP_ASYNC\n");

	if (collect_pstree())
		goto err;

	if (checkpoint_devices())
		goto err;

	if (collect_pstree_ids_predump())
		goto err;

	if (collect_namespaces(false) < 0)
		goto err;

	/* Errors handled later in detect_pid_reuse */
	parent_ie = get_parent_inventory();

	if (collect_and_suspend_lsm() < 0)
		goto err;

	for_each_pstree_item(item) {
		if (pre_dump_one_task(item, parent_ie))
			goto err;
	}

	/* Unfreeze — process runs with WP_ASYNC */
	ret = arch_set_thread_regs(root_item, false);
	if (ret)
		goto err;

	pstree_switch_state(root_item, TASK_ALIVE);

	/* Phase 2: bulk page transfer + iterative dirty scan */
	pr_debug("PHASE 2: Bulk page transfer + dirty scan convergence\n");

	/*
	 * Start the page server which starts P3 threads.
	 * P3 threads do bulk transfer then iterative dirty scanning.
	 * WP_ASYNC tracks writes without generating faults.
	 */
	ret = cr_page_server(false, true, -1);
	if (ret) {
		pr_err("Bulk page transfer failed\n");
		goto err_refreeze;
	}

	wait_for_page_server_thread();

	/*
	 * Clean up page_pipes and local parasite mappings from Phase 1.
	 * The bulk transfer is complete, so we no longer need these.
	 */
	for_each_pstree_item(item) {
		if (item->pid->state != TASK_DEAD && dmpi(item)->mem_pp) {
			destroy_page_pipe(dmpi(item)->mem_pp);
			dmpi(item)->mem_pp = NULL;
			if (dmpi(item)->parasite_ctl) {
				if (compel_cure_local(dmpi(item)->parasite_ctl))
					pr_err("Can't cure local (pid: %d)\n",
					       item->pid->real);
				dmpi(item)->parasite_ctl = NULL;
			}
		}
	}

	/*
	 * Wait for P3 threads to converge (all below dirty page threshold).
	 * Threads are running iterative dirty scan loop.
	 */
	pr_debug("Waiting for dirty page convergence\n");
	while (!clone_all_threads_below_threshold()) {
		usleep(CLONE_USLEEP_10MS);
	}
	pr_debug("CONVERGENCE: All threads below threshold\n");

	/* Phase 3: freeze + skeleton dump */
	pr_debug("PHASE 3: Freeze + skeleton dump\n");

	/*
	 * Re-seize all tasks. After Phase 1, tasks were released via
	 * pstree_switch_state(TASK_ALIVE) which detached from ptrace.
	 * We need to re-attach to perform the skeleton dump.
	 */
	ret = reseize_pstree();
	if (ret) {
		pr_err("Failed to re-seize tasks\n");
		goto err;
	}

	/*
	 * Collect pstree IDs now so vpid(item) is valid for the VMA detection.
	 * This must happen before clone_detect_new_vmas() which uses dst_id.
	 */
	if (collect_pstree_ids())
		goto err;

	/* Update CLONE dst_id now that collect_pstree_ids() has populated vpid */
	clone_set_dst_id(vpid(root_item));

	/*
	 * Detect VMAs that were created between Phase 1 and Phase 3.
	 * New VMAs weren't tracked during Phase 2, so their pages weren't
	 * sent. We mark them as dirty to ensure they get transferred
	 * and protected with WP_SYNC for convergence.
	 */
	{
		struct vm_area_list phase3_vmas;
		unsigned long *new_vma_ranges = NULL;
		unsigned int nr_new_vma_ranges = 0;

		vm_area_list_init(&phase3_vmas);

		ret = collect_mappings(root_item->pid->real, &phase3_vmas, NULL);
		if (ret) {
			pr_err("Failed to collect Phase 3 VMAs\n");
			goto err;
		}

		pr_debug("CLONE PHASE 3: Collected %lu VMAs for pid %d (compare with Phase 1 count)\n",
			 (unsigned long)phase3_vmas.nr, root_item->pid->real);

		ret = clone_detect_new_vmas(&phase3_vmas, &new_vma_ranges, &nr_new_vma_ranges);
		free_mappings(&phase3_vmas);

		if (ret) {
			pr_err("Failed to detect new VMAs\n");
			goto err;
		}

		if (nr_new_vma_ranges > 0) {
			pr_debug("CLONE PHASE 3: Found %u new VMA regions since Phase 1!\n",
				 nr_new_vma_ranges);
			pr_debug("CLONE PHASE 3: These VMAs were created while process ran during Phase 2.\n");
			pr_debug("CLONE PHASE 3: Their PAGE DATA will be sent, but VMA METADATA is missing from dump.\n");
			pr_debug("CLONE PHASE 3: target will not have these VMAs - expect comparison differences\n");

			/* Pass new VMA ranges to P3 threads for sending during final scan */
			clone_set_new_vma_ranges(new_vma_ranges, nr_new_vma_ranges);
			/* Don't free - P3 threads will use it */
		} else {
			pr_debug("CLONE PHASE 3: No new VMAs detected - VMA count unchanged since Phase 1.\n");
			xfree(new_vma_ranges);
		}
	}

	/*
	 * Signal P3 threads to do final scan (process is frozen, new VMA ranges set).
	 * Must be after clone_set_new_vma_ranges() so threads can send new VMA pages.
	 */
	clone_signal_last_scan();

	if (network_lock())
		goto err;

	if (rpc_query_external_files())
		goto err;

	if (collect_file_locks())
		goto err;

	if (collect_namespaces(true) < 0)
		goto err;

	glob_imgset = cr_glob_imgset_open(O_DUMP);
	if (!glob_imgset)
		goto err;

	if (seccomp_collect_dump_filters() < 0)
		goto err;

	/* Set phase to SCAN so clone_is_phased_skeleton_dump() returns true */
	clone_set_phase(CLONE_PHASE_SCAN);

	/* Dump skeleton (everything except pages) */
	for_each_pstree_item(item) {
		if (dump_one_task(item, parent_ie))
			goto err;
	}

	if (parent_ie) {
		inventory_entry__free_unpacked(parent_ie, NULL);
		parent_ie = NULL;
	}

	/* Standard post-task dump operations */
	if (cr_dump_post_task_operations(&he))
		goto err;

	pr_info("Skeleton dump complete\n");

	/*
	 * Wait for P3 threads to complete their final scan (process is frozen,
	 * last_scan flag was set above). Threads will send any remaining dirty pages.
	 *
	 * NOTE: Inventory write and signal moved to cr_dump_finish() - they happen
	 * AFTER all data is collected and flushed, right before unfreeze.
	 */
	pr_debug("Waiting for P3 threads final scan\n");
	clone_wait_p3_threads();
	pr_debug("P3 threads completed: %lu total pages sent\n", clone_p3_pages_sent());

	if (clone_p3_had_error()) {
		pr_err("clone-dump: P3 bulk transfer reported errors — failing "
		       "the dump rather than producing a torn image\n");
		goto err_refreeze;
	}

	/* Free new VMA ranges after P3 threads are done using them */
	clone_free_new_vma_ranges();

	/*
	 * all_pages_sent signal is sent in cr_dump_finish() after unfreeze.
	 */

	clone_set_phase(CLONE_PHASE_DONE);

	/* Set up inventory fields and write - like standard path */
	he.has_pre_dump_mode = false;
	if (found_uprobes_vma()) {
		he.has_allow_uprobes = true;
		he.allow_uprobes = true;
	}

	exit_code = write_img_inventory(&he);
	goto err;

err_refreeze:
	/*
	 * If we failed during bulk transfer, try to re-seize tasks before
	 * cleanup. Tasks were detached in Phase 1, so pstree_switch_state
	 * alone won't work.
	 */
	if (reseize_pstree())
		pr_warn("Failed to re-seize tasks during error cleanup\n");
err:
	if (parent_ie)
		inventory_entry__free_unpacked(parent_ie, NULL);

	return cr_dump_finish(exit_code);
}
