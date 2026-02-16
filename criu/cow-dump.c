#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <time.h>
#include <string.h>
#include <poll.h>

#include "types.h"
#include "cr_options.h"
#include "pstree.h"
#include "cow-dump.h"
#include "mman.h"
#include "uffd.h"
#include "page-xfer.h"
#include "page-pipe.h"
#include "parasite-syscall.h"
#include "mem.h"
#include "vma.h"
#include "util.h"
#include "kerndat.h"
#include "criu-log.h"
#include "parasite.h"

#undef LOG_PREFIX
#define LOG_PREFIX "cow-dump: "

struct cow_tracked_vma {
	unsigned long start;
	unsigned long end;
};

struct cow_tracked_task {
	pid_t source_pid;
	int uffd;
	unsigned long total_pages;
	unsigned int nr_tracked_vmas;
	struct cow_tracked_vma *tracked_vmas;
	struct list_head list;
};

/* COW dump state for one dump session */
struct cow_dump_info {
	struct list_head tracked_tasks;
	unsigned long total_pages;
	unsigned long iteration;
	struct hlist_head cow_hash[COW_HASH_SIZE];	/* Hash table for copied pages */
	pthread_spinlock_t cow_hash_locks[COW_HASH_SIZE];	/* Per-bucket spinlocks */
	struct list_head cow_page_queue;	/* FIFO queue of COW pages */
	pthread_spinlock_t queue_lock;		/* Protects the queue */
};


static struct cow_dump_info *g_cow_info = NULL;
static pthread_t g_monitor_thread;
static volatile bool g_monitor_thread_running = false;
static volatile bool g_stop_monitoring = false;
static pthread_mutex_t g_monitor_state_lock = PTHREAD_MUTEX_INITIALIZER;

#define COW_CONVERGENCE_THRESHOLD 100  /* Stop if < 100 pages dirty per iteration */
#define COW_FLUSH_THRESHOLD 1000       /* Flush to disk every 1000 pages */

/* Statistics tracking structure */
static struct {
	/* Event counters */
	unsigned long write_faults;
	unsigned long fork_events;
	unsigned long remap_events;
	unsigned long unknown_events;
	
	/* Operation counters */
	unsigned long pages_copied;
	unsigned long pages_unprotected;
	unsigned long pages_woken;
	
	/* Error counters */
	unsigned long alloc_failures;
	unsigned long read_failures;
	unsigned long unprotect_failures;
	unsigned long wake_failures;
	unsigned long eagain_errors;
	unsigned long read_errors;
	
	time_t last_print_time;
} cow_stats;

static void check_and_print_cow_stats(void)
{
	time_t now = time(NULL);
	
	if (now - cow_stats.last_print_time >= 1) {
		pr_debug("[COW_STATS] events: wr=%lu fork=%lu remap=%lu unk=%lu | ops: copied=%lu unprot=%lu woken=%lu | errs: alloc=%lu read=%lu unprot_err=%lu wake_err=%lu read_err=%lu eagain_err=%lu\n",
			cow_stats.write_faults,
			cow_stats.fork_events,
			cow_stats.remap_events,
			cow_stats.unknown_events,
			cow_stats.pages_copied,
			cow_stats.pages_unprotected,
			cow_stats.pages_woken,
			cow_stats.alloc_failures,
			cow_stats.read_failures,
			cow_stats.unprotect_failures,
			cow_stats.wake_failures,
			cow_stats.read_errors,
			cow_stats.eagain_errors);
		
		/* Reset all counters */
		memset(&cow_stats, 0, sizeof(cow_stats));
		cow_stats.last_print_time = now;
	}
}

static struct cow_tracked_task *cow_find_task_by_pid(pid_t source_pid)
{
	struct cow_tracked_task *task;

	if (!g_cow_info)
		return NULL;

	list_for_each_entry(task, &g_cow_info->tracked_tasks, list) {
		if (task->source_pid == source_pid)
			return task;
	}

	return NULL;
}

bool cow_check_kernel_support(void)
{
	unsigned long features = UFFD_FEATURE_PAGEFAULT_FLAG_WP;
	int uffd, err = 0;

	uffd = uffd_open(0, &features, &err);
	if (uffd < 0) {
		if (err == ENOSYS) {
			pr_info("userfaultfd not supported by kernel\n");
		} else if (err == EPERM) {
			pr_info("userfaultfd requires CAP_SYS_PTRACE or sysctl vm.unprivileged_userfaultfd=1\n");
		}
		return false;
	}

	if (!(features & UFFD_FEATURE_PAGEFAULT_FLAG_WP)) {
		pr_info("userfaultfd WP pagefault flag not supported (need kernel 5.7+)\n");
		close(uffd);
		return false;
	}

	close(uffd);
	pr_info("COW dump kernel support detected\n");
	return true;
}

int cow_dump_init(struct pstree_item *item, struct vm_area_list *vma_area_list, struct parasite_ctl *ctl)
{
	struct cow_dump_info *cdi = g_cow_info;
	struct cow_tracked_task *task = NULL;
	struct vma_area *vma;
	struct parasite_cow_dump_args *args;
	struct parasite_vma_entry *p_vma;
	unsigned int *failed_indices;
	bool created_session = false;
	int ret;
	unsigned long args_size;
	unsigned int nr_vmas = 0;
	unsigned int tracked_vmas = 0;
	unsigned int fallback_vmas = 0;
	bool *failed_map = NULL;
	unsigned int i;

	pr_info("Initializing COW dump for pid %d (via parasite)\n", item->pid->real);

	pthread_mutex_lock(&g_monitor_state_lock);
	if (g_monitor_thread_running) {
		pthread_mutex_unlock(&g_monitor_state_lock);
		pr_err("COW monitor thread is already running; refusing late task registration\n");
		return -1;
	}
	pthread_mutex_unlock(&g_monitor_state_lock);

	if (!cdi) {
		if (!cow_check_kernel_support()) {
			pr_err("Kernel doesn't support COW dump\n");
			return -1;
		}

		cdi = xzalloc(sizeof(*cdi));
		if (!cdi)
			return -1;

		INIT_LIST_HEAD(&cdi->tracked_tasks);
		for (i = 0; i < COW_HASH_SIZE; i++) {
			INIT_HLIST_HEAD(&cdi->cow_hash[i]);
			pthread_spin_init(&cdi->cow_hash_locks[i], PTHREAD_PROCESS_PRIVATE);
		}
		INIT_LIST_HEAD(&cdi->cow_page_queue);
		pthread_spin_init(&cdi->queue_lock, PTHREAD_PROCESS_PRIVATE);
		g_cow_info = cdi;
		created_session = true;
	}

	if (cow_find_task_by_pid(item->pid->real)) {
		pr_warn("COW tracking already initialized for pid %d, skipping\n", item->pid->real);
		return 0;
	}

	task = xzalloc(sizeof(*task));
	if (!task)
		goto err;

	INIT_LIST_HEAD(&task->list);
	task->source_pid = item->pid->real;
	task->uffd = -1;

	/* Prepare parasite arguments - count writable VMAs */
	/* IMPORTANT: Apply same filters as generate_vma_iovs() to avoid mismatches */
	nr_vmas = 0;
	list_for_each_entry(vma, &vma_area_list->h, list) {
		if (!vma_entry_can_be_lazy(vma->e))
		{		
			continue;
		}
		if (vma_area_is(vma, VMA_AREA_GUARD))
			continue;
		
		/* Must be writable */
		if (!(vma->e->prot & PROT_WRITE))
			continue;
		
		/* Match generate_vma_iovs() filters */
		if (!vma_area_is_private(vma, kdat.task_size) && !vma_area_is(vma, VMA_ANON_SHARED))
			continue;
		
		if (vma_entry_is(vma->e, VMA_AREA_VVAR))
			continue;
		
		if (vma->e->flags & MAP_DROPPABLE)
			continue;
		
		nr_vmas++;
	}

	/* Allocate parasite args - includes space for VMAs and failed indices */
	args_size = sizeof(*args) + 
		    nr_vmas * sizeof(struct parasite_vma_entry) +
		    nr_vmas * sizeof(unsigned int);  /* Space for failed indices */
	args = compel_parasite_args_s(ctl, args_size);
	if (!args) {
		pr_err("Failed to allocate parasite args\n");
		goto err;
	}

	args->nr_vmas = nr_vmas;
	args->total_pages = 0;
	args->nr_failed_vmas = 0;
	args->ret = -1;

	/* Fill VMA entries - must match the filters used above */
	p_vma = cow_dump_vmas(args);
	nr_vmas = 0;
	list_for_each_entry(vma, &vma_area_list->h, list) {
		if (!vma_entry_can_be_lazy(vma->e))
		{
			continue;
		}
		if (vma_area_is(vma, VMA_AREA_GUARD))
			continue;
		
		if (!(vma->e->prot & PROT_WRITE))
			continue;
		
		/* Match generate_vma_iovs() filters */
		if (!vma_area_is_private(vma, kdat.task_size) && !vma_area_is(vma, VMA_ANON_SHARED))
			continue;
		
		if (vma_entry_is(vma->e, VMA_AREA_VVAR))
			continue;
		
		if (vma->e->flags & MAP_DROPPABLE)
			continue;

		p_vma[nr_vmas].start = vma->e->start;
		p_vma[nr_vmas].len = vma->e->end - vma->e->start;
		p_vma[nr_vmas].prot = vma->e->prot;
		nr_vmas++;
	}

	pr_info("Calling parasite to register %u VMAs\n", args->nr_vmas);

	/* Call parasite to create uffd and perform registration (async) */
	ret = compel_rpc_call(PARASITE_CMD_COW_DUMP_INIT, ctl);
	if (ret < 0) {
		pr_err("Failed to initiate COW dump RPC\n");
		goto err;
	}

	/* Receive userfaultfd from parasite */
	compel_util_recv_fd(ctl, &task->uffd);
	if (task->uffd < 0) {
		pr_err("Failed to receive userfaultfd from parasite: %d\n", task->uffd);
		goto err;
	}
	pr_info("Got fd %d VMAs\n", task->uffd);
	/* Wait for parasite to complete */
	ret = compel_rpc_sync(PARASITE_CMD_COW_DUMP_INIT, ctl);
	if (ret < 0 || args->ret != 0) {
		pr_err("Parasite COW dump init failed: %d (ret=%d)\n", ret, args->ret);
		goto err;
	}

	task->total_pages = args->total_pages;

	if (args->nr_vmas > 0) {
		failed_map = xzalloc(args->nr_vmas * sizeof(*failed_map));
		if (!failed_map)
			goto err;
	}

	failed_indices = cow_dump_failed_indices(args);
	for (i = 0; i < args->nr_failed_vmas; i++) {
		unsigned int idx = failed_indices[i];

		if (idx >= args->nr_vmas) {
			pr_warn("Ignoring invalid failed VMA index %u (nr_vmas=%u)\n", idx, args->nr_vmas);
			continue;
		}

		if (!failed_map[idx]) {
			failed_map[idx] = true;
			fallback_vmas++;
		}
	}

	tracked_vmas = args->nr_vmas - fallback_vmas;
	if (tracked_vmas > 0) {
		unsigned int tracked_idx = 0;

		task->tracked_vmas = xzalloc(sizeof(*task->tracked_vmas) * tracked_vmas);
		if (!task->tracked_vmas)
			goto err;

		p_vma = cow_dump_vmas(args);
		for (i = 0; i < args->nr_vmas; i++) {
			if (failed_map[i])
				continue;

			task->tracked_vmas[tracked_idx].start = p_vma[i].start;
			task->tracked_vmas[tracked_idx].end = p_vma[i].start + p_vma[i].len;
			tracked_idx++;
		}
		task->nr_tracked_vmas = tracked_vmas;
	}

	list_add_tail(&task->list, &cdi->tracked_tasks);
	cdi->total_pages += task->total_pages;

	pr_info("COW dump initialized for pid %d: vm_as=%u tracked=%u fallback=%u pages=%lu uffd=%d\n",
		item->pid->real, args->nr_vmas, tracked_vmas, fallback_vmas,
		task->total_pages, task->uffd);
	pr_info("COW dump tracking armed\n");

	xfree(failed_map);
	return 0;

err:
	if (task) {
		if (task->uffd >= 0)
			close(task->uffd);
		xfree(task->tracked_vmas);
		xfree(task);
	}

	xfree(failed_map);

	if (created_session) {
		for (i = 0; i < COW_HASH_SIZE; i++)
			pthread_spin_destroy(&cdi->cow_hash_locks[i]);
		pthread_spin_destroy(&cdi->queue_lock);
		xfree(cdi);
		g_cow_info = NULL;
	}

	return -1;
}

void cow_dump_fini(void)
{	
	struct cow_page *cp;
	struct cow_page_queue_entry *qe, *qe_tmp;
	struct cow_tracked_task *task, *task_tmp;
	struct hlist_node *n;
	int i, remaining = 0, queue_remaining = 0;

	if (!g_cow_info)
		return;

	if (cow_stop_monitor_thread()) {
		pr_err("Failed to stop COW monitor thread, skipping COW cleanup to avoid races\n");
		return;
	}

	pr_info("Cleaning up COW dump\n");

	/* Clean up any remaining queue entries */
	pthread_spin_lock(&g_cow_info->queue_lock);
	list_for_each_entry_safe(qe, qe_tmp, &g_cow_info->cow_page_queue, list) {
		list_del(&qe->list);
		xfree(qe);
		queue_remaining++;
	}
	pthread_spin_unlock(&g_cow_info->queue_lock);
	pthread_spin_destroy(&g_cow_info->queue_lock);

	if (queue_remaining > 0)
		pr_warn("Freed %d remaining queue entries\n", queue_remaining);

	/* Clean up any remaining COW pages */
	for (i = 0; i < COW_HASH_SIZE; i++) {
		pthread_spin_lock(&g_cow_info->cow_hash_locks[i]);
		hlist_for_each_entry_safe(cp, n, &g_cow_info->cow_hash[i], hash) {
			hlist_del(&cp->hash);
			xfree(cp->data);
			xfree(cp);
			remaining++;
		}
		pthread_spin_unlock(&g_cow_info->cow_hash_locks[i]);
		pthread_spin_destroy(&g_cow_info->cow_hash_locks[i]);
	}

	if (remaining > 0)
		pr_warn("Freed %d remaining COW pages\n", remaining);

	list_for_each_entry_safe(task, task_tmp, &g_cow_info->tracked_tasks, list) {
		list_del(&task->list);
		if (task->uffd >= 0)
			close(task->uffd);
		xfree(task->tracked_vmas);
		xfree(task);
	}

	xfree(g_cow_info);
	g_cow_info = NULL;
}

static int cow_handle_write_fault(struct cow_dump_info *cdi,
				  struct cow_tracked_task *task,
				  unsigned long addr)
{
	struct cow_page *cp;
	unsigned long page_addr = addr & ~(PAGE_SIZE - 1);
	struct uffdio_writeprotect wp;
	struct uffdio_range range;
	ssize_t ret;
	unsigned int hash;
	struct iovec local_iov, remote_iov;

	pr_debug("Write fault at 0x%lx\n", page_addr);

	cow_stats.write_faults++;	

	/* Allocate cow_page structure */
	cp = xmalloc(sizeof(*cp));
	if (!cp) {
		pr_err("Failed to allocate cow_page structure\n");
		cow_stats.alloc_failures++;
		return -1;
	}

	cp->data = xmalloc(PAGE_SIZE);
	if (!cp->data) {
		pr_err("Failed to allocate page data\n");
		xfree(cp);
		cow_stats.alloc_failures++;
		return -1;
	}

	cp->vaddr = page_addr;
	INIT_HLIST_NODE(&cp->hash);

	/* Read original page content using process_vm_readv */
	
	local_iov.iov_base = cp->data;
	local_iov.iov_len = PAGE_SIZE;
	remote_iov.iov_base = (void *)page_addr;
	remote_iov.iov_len = PAGE_SIZE;
	
	ret = process_vm_readv(task->source_pid, &local_iov, 1, &remote_iov, 1, 0);
	if (ret != PAGE_SIZE) {
		pr_perror("Failed to read page at 0x%lx from pid %d (read %zd bytes)", 
			  page_addr, task->source_pid, ret);
		xfree(cp->data);
		xfree(cp);
		cow_stats.read_failures++;
		return -1;
	}

	/* Add to hash table (thread-safe with per-bucket spinlock) */
	hash = (page_addr >> PAGE_SHIFT) & (COW_HASH_SIZE - 1);
	
	pthread_spin_lock(&cdi->cow_hash_locks[hash]);
	hlist_add_head(&cp->hash, &cdi->cow_hash[hash]);
	pthread_spin_unlock(&cdi->cow_hash_locks[hash]);

	cow_stats.pages_copied++;
	pr_debug("Copied page at 0x%lx to hash bucket %u\n", page_addr, hash);

	/* Unprotect the page so the process can continue */
	wp.range.start = page_addr;
	wp.range.len = PAGE_SIZE;
	wp.mode = 0; /* Clear write-protect */

	if (ioctl(task->uffd, UFFDIO_WRITEPROTECT, &wp)) {
		pr_perror("Failed to unprotect page at 0x%lx", page_addr);
		cow_stats.unprotect_failures++;
		return -1;
	}

	cow_stats.pages_unprotected++;

	/* Wake up the faulting thread */
	range.start = page_addr;
	range.len = PAGE_SIZE;
	
	if (ioctl(task->uffd, UFFDIO_WAKE, &range)) {
		pr_perror("Failed to wake thread after unprotect");
		cow_stats.wake_failures++;
		return -1;
	}
	
	cow_stats.pages_woken++;
	cdi->total_pages--;

	return 0;
}

static int cow_process_events(struct cow_dump_info *cdi,
			      struct cow_tracked_task *task,
			      bool blocking)
{
	struct uffd_msg msg;
	struct pollfd pfd;
	int ret, poll_ret;

	while (1) {
		/* Check and print stats */
		check_and_print_cow_stats();
		
		/* Try reading directly first - avoids poll() overhead when data is ready */
		ret = read(task->uffd, &msg, sizeof(msg));
		
		if (ret < 0 && errno == EAGAIN && blocking) {
			/* No data available and we want to block - use poll() with timeout */
			pfd.fd = task->uffd;
			pfd.events = POLLIN;
			pfd.revents = 0;
			
			poll_ret = poll(&pfd, 1, 500);  /* 500ms timeout */
			if (poll_ret < 0) {
				pr_perror("poll() failed on uffd");
				cow_stats.read_errors++;
				return -1;
			}
			
			if (poll_ret == 0) {
				/* Timeout - no events within 500ms */
				return 0;
			}
			
			/* Data ready after poll - retry read */
			ret = read(task->uffd, &msg, sizeof(msg));
		}
		
		if (ret < 0) {
			if (errno == EAGAIN && !blocking) {
				/* Non-blocking mode and no data */
				cow_stats.eagain_errors++;
				return 0;
			}
			pr_perror("Failed to read uffd event");
			cow_stats.read_errors++;
			return -1;
		}

		if (ret != sizeof(msg)) {
			pr_err("Short read from uffd: %d\n", ret);
			cow_stats.read_errors++;
			return -1;
		}

		switch (msg.event) {
		case UFFD_EVENT_PAGEFAULT:
			if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) {
				/* Write fault - track it */
				if (cow_handle_write_fault(cdi, task, msg.arg.pagefault.address))
					return -1;
			}
			break;

		case UFFD_EVENT_FORK:
			cow_stats.fork_events++;
			pr_warn("Process forked during COW dump (not fully supported)\n");
			break;

		case UFFD_EVENT_REMAP:
			cow_stats.remap_events++;
			pr_info("Memory remap event\n");
			break;

		default:
			cow_stats.unknown_events++;
			pr_err("Unexpected uffd event: %u\n", msg.event);
			return -1;
		}
	}

	return 0;
}

static int cow_wait_for_events(struct cow_dump_info *cdi, int timeout_ms)
{
	struct cow_tracked_task *task;
	struct pollfd *pfds;
	int nr_tasks = 0;
	int idx = 0;
	int ret;

	list_for_each_entry(task, &cdi->tracked_tasks, list)
		nr_tasks++;

	if (!nr_tasks)
		return 0;

	pfds = xmalloc(sizeof(*pfds) * nr_tasks);
	if (!pfds)
		return -1;

	list_for_each_entry(task, &cdi->tracked_tasks, list) {
		pfds[idx].fd = task->uffd;
		pfds[idx].events = POLLIN;
		pfds[idx].revents = 0;
		idx++;
	}

	ret = poll(pfds, nr_tasks, timeout_ms);
	if (ret < 0)
		pr_perror("poll() failed on uffd set");

	xfree(pfds);
	return ret;
}

/* Background thread that monitors for write faults */
static void *cow_monitor_thread(void *arg)
{
	struct cow_dump_info *cdi = (struct cow_dump_info *)arg;
	struct cow_tracked_task *task;
	bool monitor_error = false;

	pthread_setname_np(pthread_self(), "criu-cow-mon");
	pr_info("COW monitor thread started\n");

	while (!g_stop_monitoring) {
		int ret;

		ret = cow_wait_for_events(cdi, 500);
		if (ret < 0) {
			monitor_error = true;
			break;
		}
		if (ret == 0)
			continue;

		list_for_each_entry(task, &cdi->tracked_tasks, list) {
			if (cow_process_events(cdi, task, false) < 0) {
				pr_err("Error processing COW events for pid %d\n", task->source_pid);
				monitor_error = true;
				break;
			}
		}

		if (monitor_error)
			break;
	}
	
	if (monitor_error)
		pr_err("COW monitor thread exiting on event-processing error\n");

	pr_info("COW monitor thread stopped\n");
	return NULL;
}

int cow_start_monitor_thread(void)
{
	int ret;
	
	pthread_mutex_lock(&g_monitor_state_lock);

	if (!g_cow_info) {
		pthread_mutex_unlock(&g_monitor_state_lock);
		pr_err("COW dump not initialized\n");
		return -1;
	}

	if (list_empty(&g_cow_info->tracked_tasks)) {
		pthread_mutex_unlock(&g_monitor_state_lock);
		pr_err("COW tracking has no registered tasks\n");
		return -1;
	}

	if (g_monitor_thread_running) {
		pthread_mutex_unlock(&g_monitor_state_lock);
		return 0;
	}
	
	g_stop_monitoring = false;
	
	ret = pthread_create(&g_monitor_thread, NULL, cow_monitor_thread, g_cow_info);
	if (ret) {
		pthread_mutex_unlock(&g_monitor_state_lock);
		pr_err("Failed to create COW monitor thread: %s\n", strerror(ret));
		return -1;
	}

	g_monitor_thread_running = true;
	pthread_mutex_unlock(&g_monitor_state_lock);
	
	pr_info("COW monitor thread created successfully\n");
	return 0;
}

int cow_stop_monitor_thread(void)
{
	void *retval;
	pthread_t monitor_thread;
	int ret;
	
	pthread_mutex_lock(&g_monitor_state_lock);
	if (!g_monitor_thread_running) {
		g_stop_monitoring = false;
		pthread_mutex_unlock(&g_monitor_state_lock);
		return 0;
	}
	
	pr_info("Stopping COW monitor thread\n");
	g_stop_monitoring = true;
	monitor_thread = g_monitor_thread;
	pthread_mutex_unlock(&g_monitor_state_lock);
	
	/* Wait for thread to finish */
	ret = pthread_join(monitor_thread, &retval);
	if (ret && ret != ESRCH && ret != EINVAL) {
		pr_err("Failed to join COW monitor thread: %s\n", strerror(ret));
		return -1;
	}

	pthread_mutex_lock(&g_monitor_state_lock);
	g_monitor_thread_running = false;
	g_stop_monitoring = false;
	pthread_mutex_unlock(&g_monitor_state_lock);
	
	pr_info("COW monitor thread stopped successfully\n");
	return 0;
}

int cow_get_uffd(void)
{
	struct cow_tracked_task *task;

	if (!g_cow_info || list_empty(&g_cow_info->tracked_tasks))
		return -1;

	task = list_first_entry(&g_cow_info->tracked_tasks, struct cow_tracked_task, list);
	return task->uffd;
}

int cow_get_uffd_for_pid(pid_t source_pid)
{
	struct cow_tracked_task *task;

	task = cow_find_task_by_pid(source_pid);
	if (!task)
		return -1;

	return task->uffd;
}

bool cow_dump_is_vma_tracked(pid_t source_pid, unsigned long start, unsigned long end)
{
	struct cow_tracked_task *task;
	unsigned int i;

	task = cow_find_task_by_pid(source_pid);
	if (!task)
		return false;

	for (i = 0; i < task->nr_tracked_vmas; i++) {
		if (task->tracked_vmas[i].start == start &&
		    task->tracked_vmas[i].end == end)
			return true;
	}

	return false;
}

pthread_spinlock_t *cow_get_hash_lock(unsigned long vaddr)
{
	unsigned long page_addr = vaddr & ~(PAGE_SIZE - 1);
	unsigned int hash;

	if (!g_cow_info)
		return NULL;

	hash = (page_addr >> PAGE_SHIFT) & (COW_HASH_SIZE - 1);
	return &g_cow_info->cow_hash_locks[hash];
}

struct cow_page *cow_lookup_page(unsigned long vaddr)
{
	struct cow_page *cp;
	unsigned long page_addr = vaddr & ~(PAGE_SIZE - 1);
	unsigned int hash;

	if (!g_cow_info)
		return NULL;

	hash = (page_addr >> PAGE_SHIFT) & (COW_HASH_SIZE - 1);

	/* NOTE: Caller must hold the lock for this hash bucket */
	hlist_for_each_entry(cp, &g_cow_info->cow_hash[hash], hash) {
		if (cp->vaddr == page_addr)
			return cp;
	}

	return NULL;
}

void cow_remove_page(unsigned long vaddr)
{
	struct cow_page *cp;
	struct hlist_node *n;
	unsigned long page_addr = vaddr & ~(PAGE_SIZE - 1);
	unsigned int hash;

	if (!g_cow_info)
		return;

	hash = (page_addr >> PAGE_SHIFT) & (COW_HASH_SIZE - 1);

	/* NOTE: Caller must hold the lock for this hash bucket */
	hlist_for_each_entry_safe(cp, n, &g_cow_info->cow_hash[hash], hash) {
		if (cp->vaddr == page_addr) {
			hlist_del(&cp->hash);
			xfree(cp->data);
			xfree(cp);
			pr_debug("Removed COW page at 0x%lx from hash bucket %u\n",
				 page_addr, hash);
			return;
		}
	}
}

struct cow_page *cow_lookup_and_remove_page(unsigned long vaddr)
{
	struct cow_page *cp;
	struct hlist_node *n;
	unsigned int hash;
	unsigned long page_addr = vaddr & ~(PAGE_SIZE - 1);

	if (!g_cow_info)
		return NULL;

	hash = (page_addr >> PAGE_SHIFT) & (COW_HASH_SIZE - 1);

	pthread_spin_lock(&g_cow_info->cow_hash_locks[hash]);
	
	hlist_for_each_entry_safe(cp, n, &g_cow_info->cow_hash[hash], hash) {
		if (cp->vaddr == page_addr) {
			hlist_del(&cp->hash);
			pthread_spin_unlock(&g_cow_info->cow_hash_locks[hash]);
			pr_debug("Found and removed COW page at 0x%lx from hash bucket %u\n", 
				 page_addr, hash);
			return cp;
		}
	}
	
	pthread_spin_unlock(&g_cow_info->cow_hash_locks[hash]);
	return NULL;
}

struct cow_page_queue_entry *cow_get_next_page(void)
{
	struct cow_page_queue_entry *entry = NULL;

	if (!g_cow_info)
		return NULL;

	pthread_spin_lock(&g_cow_info->queue_lock);
	if (!list_empty(&g_cow_info->cow_page_queue)) {
		entry = list_first_entry(&g_cow_info->cow_page_queue,
					 struct cow_page_queue_entry, list);
		list_del(&entry->list);
	}
	pthread_spin_unlock(&g_cow_info->queue_lock);

	return entry;
}

bool cow_has_pending_pages(void)
{
	bool has_pages;

	if (!g_cow_info)
		return false;

	pthread_spin_lock(&g_cow_info->queue_lock);
	has_pages = !list_empty(&g_cow_info->cow_page_queue);
	pthread_spin_unlock(&g_cow_info->queue_lock);

	return has_pages;
}

void cow_put_back_page(struct cow_page_queue_entry *entry)
{
	if (!g_cow_info || !entry)
		return;

	pthread_spin_lock(&g_cow_info->queue_lock);
	list_add(&entry->list, &g_cow_info->cow_page_queue);
	pthread_spin_unlock(&g_cow_info->queue_lock);

	pr_debug("Re-queued COW page 0x%lx\n", entry->vaddr);
}

unsigned long cow_get_queue_size(void)
{
	unsigned long count = 0;
	struct cow_page_queue_entry *entry;

	if (!g_cow_info)
		return 0;

	pthread_spin_lock(&g_cow_info->queue_lock);
	list_for_each_entry(entry, &g_cow_info->cow_page_queue, list) {
		count++;
	}
	pthread_spin_unlock(&g_cow_info->queue_lock);

	return count;
}
