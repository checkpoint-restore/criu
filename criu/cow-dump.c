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

#include "types.h"
#include "cr_options.h"
#include "pstree.h"
#include "cow-dump.h"
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

/* COW dump state for a single process */
struct cow_dump_info {
	struct pstree_item *item;
	int uffd;				/* userfaultfd for write tracking */
	int proc_mem_fd;			/* /proc/pid/mem for reading pages */
	unsigned long total_pages;		/* Total pages being tracked */
	unsigned long dirty_pages;		/* Pages modified in current iteration */
	unsigned long dirty_pages_dumped;	/* Pages already written to disk */
	unsigned long iteration;		/* Current iteration number */
	struct list_head dirty_list;		/* List of dirty page ranges */
	struct hlist_head cow_hash[COW_HASH_SIZE];	/* Hash table for copied pages */
	pthread_mutex_t cow_hash_lock;		/* Protect hash table access */
};

/* Dirty page range */
struct dirty_range {
	unsigned long start;
	unsigned long len;
	struct list_head list;
};

static struct cow_dump_info *g_cow_info = NULL;
static pthread_t g_monitor_thread;
static volatile bool g_stop_monitoring = false;

#define COW_MAX_ITERATIONS 10
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
		pr_warn("[COW_STATS] events: wr=%lu fork=%lu remap=%lu unk=%lu | ops: copied=%lu unprot=%lu woken=%lu | errs: alloc=%lu read=%lu unprot_err=%lu wake_err=%lu read_err=%lu eagain_err=%lu\n",
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

bool cow_check_kernel_support(void)
{
	unsigned long features = UFFD_FEATURE_WP_ASYNC |
				 UFFD_FEATURE_PAGEFAULT_FLAG_WP | 
				 UFFD_FEATURE_EVENT_FORK |
				 UFFD_FEATURE_EVENT_REMAP;
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

	if (!(features & UFFD_FEATURE_WP_ASYNC)) {
		pr_info("userfaultfd write-protect feature not supported (need kernel 5.7+)\n");
		close(uffd);
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

static int open_proc_mem(pid_t pid)
{
	char path[64];
	int fd;

	snprintf(path, sizeof(path), "/proc/%d/mem", pid);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("Failed to open %s", path);
		return -1;
	}

	return fd;
}

int cow_dump_init(struct pstree_item *item, struct vm_area_list *vma_area_list, struct parasite_ctl *ctl)
{
	struct cow_dump_info *cdi;
	struct vma_area *vma;
	struct parasite_cow_dump_args *args;
	struct parasite_vma_entry *p_vma;

	int ret;
	unsigned long args_size;
	unsigned int nr_vmas = 0;

	pr_info("Initializing COW dump for pid %d (via parasite)\n", item->pid->real);

	if (!cow_check_kernel_support()) {
		pr_err("Kernel doesn't support COW dump\n");
		return -1;
	}

	cdi = xzalloc(sizeof(*cdi));
	if (!cdi)
		return -1;

	cdi->item = item;
	INIT_LIST_HEAD(&cdi->dirty_list);
	cdi->uffd = -1; /* Will be received from parasite */

	/* Initialize hash table for COW pages */
	for (int i = 0; i < COW_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&cdi->cow_hash[i]);
	
	pthread_mutex_init(&cdi->cow_hash_lock, NULL);

	/* Open /proc/pid/mem for reading pages */
	cdi->proc_mem_fd = open_proc_mem(item->pid->real);
	if (cdi->proc_mem_fd < 0)
		goto err_free;

	/* Prepare parasite arguments - count writable VMAs */
	nr_vmas = 0;
	list_for_each_entry(vma, &vma_area_list->h, list) {
		if (vma_area_is(vma, VMA_AREA_GUARD))
			continue;
		if (vma->e->prot & PROT_WRITE)
			nr_vmas++;
	}

	/* Allocate parasite args - includes space for VMAs and failed indices */
	args_size = sizeof(*args) + 
		    nr_vmas * sizeof(struct parasite_vma_entry) +
		    nr_vmas * sizeof(unsigned int);  /* Space for failed indices */
	args = compel_parasite_args_s(ctl, args_size);
	if (!args) {
		pr_err("Failed to allocate parasite args\n");
		goto err_close_mem;
	}

	args->nr_vmas = nr_vmas;
	args->total_pages = 0;
	args->nr_failed_vmas = 0;
	args->ret = -1;

	/* Fill VMA entries */
	p_vma = cow_dump_vmas(args);
	nr_vmas = 0;
	list_for_each_entry(vma, &vma_area_list->h, list) {
		if (vma_area_is(vma, VMA_AREA_GUARD))
			continue;
		if (!(vma->e->prot & PROT_WRITE))
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
		goto err_close_mem;
	}

	/* Receive userfaultfd from parasite */
	compel_util_recv_fd(ctl, &cdi->uffd);
	if (cdi->uffd < 0) {
		pr_err("Failed to receive userfaultfd from parasite: %d\n", cdi->uffd);
		goto err_close_mem;
	}
	pr_info("Got fd %d VMAs\n", cdi->uffd);
	/* Wait for parasite to complete */
	ret = compel_rpc_sync(PARASITE_CMD_COW_DUMP_INIT, ctl);
	if (ret < 0 || args->ret != 0) {
		pr_err("Parasite COW dump init failed: %d (ret=%d)\n", ret, args->ret);
		close(cdi->uffd);
		cdi->uffd = -1;
		goto err_close_mem;
	}

	cdi->total_pages = args->total_pages;
	cdi->dirty_pages_dumped = 0;
		
	pr_info("COW dump initialized: tracking %lu pages, uffd=%d\n", 
		cdi->total_pages, cdi->uffd);
	
	
	g_cow_info = cdi;
	return 0;

err_close_mem:
	close(cdi->proc_mem_fd);
err_free:
	xfree(cdi);
	return -1;
}

void cow_dump_fini(void)
{
	struct dirty_range *dr, *tmp;
	struct cow_page *cp;
	struct hlist_node *n;
	int i, remaining = 0;

	if (!g_cow_info)
		return;

	pr_info("Cleaning up COW dump\n");

	/* Clean up any remaining COW pages */
	pthread_mutex_lock(&g_cow_info->cow_hash_lock);
	for (i = 0; i < COW_HASH_SIZE; i++) {
		hlist_for_each_entry_safe(cp, n, &g_cow_info->cow_hash[i], hash) {
			hlist_del(&cp->hash);
			xfree(cp->data);
			xfree(cp);
			remaining++;
		}
	}
	pthread_mutex_unlock(&g_cow_info->cow_hash_lock);

	if (remaining > 0)
		pr_warn("Freed %d remaining COW pages\n", remaining);

	pthread_mutex_destroy(&g_cow_info->cow_hash_lock);

	list_for_each_entry_safe(dr, tmp, &g_cow_info->dirty_list, list) {
		list_del(&dr->list);
		xfree(dr);
	}
	
	if (g_cow_info->proc_mem_fd >= 0)
		close(g_cow_info->proc_mem_fd);
	
	if (g_cow_info->uffd >= 0)
		close(g_cow_info->uffd);

	xfree(g_cow_info);
	g_cow_info = NULL;
}

static int cow_handle_write_fault(struct cow_dump_info *cdi, unsigned long addr)
{
	struct cow_page *cp;
	unsigned long page_addr = addr & ~(PAGE_SIZE - 1);
	struct uffdio_writeprotect wp;
	struct uffdio_range range;
	ssize_t ret;
	unsigned int hash;
	
	pr_info("Write fault at 0x%lx\n", page_addr);

	cow_stats.write_faults++;
	cdi->dirty_pages++;

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

	/* Read original page content from /proc/pid/mem */
	ret = pread(cdi->proc_mem_fd, cp->data, PAGE_SIZE, page_addr);
	if (ret != PAGE_SIZE) {
		pr_perror("Failed to read page at 0x%lx (read %zd bytes)", page_addr, ret);
		xfree(cp->data);
		xfree(cp);
		cow_stats.read_failures++;
		return -1;
	}

	/* Add to hash table (thread-safe) */
	hash = (page_addr >> PAGE_SHIFT) & (COW_HASH_SIZE - 1);
	
	pthread_mutex_lock(&cdi->cow_hash_lock);
	hlist_add_head(&cp->hash, &cdi->cow_hash[hash]);
	pthread_mutex_unlock(&cdi->cow_hash_lock);

	cow_stats.pages_copied++;
	pr_debug("Copied page at 0x%lx to hash bucket %u\n", page_addr, hash);

	/* Unprotect the page so the process can continue */
	wp.range.start = page_addr;
	wp.range.len = PAGE_SIZE;
	wp.mode = 0; /* Clear write-protect */

	if (ioctl(cdi->uffd, UFFDIO_WRITEPROTECT, &wp)) {
		pr_perror("Failed to unprotect page at 0x%lx", page_addr);
		cow_stats.unprotect_failures++;
		return -1;
	}

	cow_stats.pages_unprotected++;

	/* Wake up the faulting thread */
	range.start = page_addr;
	range.len = PAGE_SIZE;
	
	if (ioctl(cdi->uffd, UFFDIO_WAKE, &range)) {
		pr_perror("Failed to wake thread after unprotect");
		cow_stats.wake_failures++;
		return -1;
	}
	
	cow_stats.pages_woken++;
	cdi->total_pages--;
	return 0;
}

static int cow_process_events(struct cow_dump_info *cdi, bool blocking)
{
	struct uffd_msg msg;
	int ret;
	//int flags = blocking ? MSG_WAITALL : MSG_DONTWAIT;

	while (1) {
		/* Check and print stats */
		check_and_print_cow_stats();
		ret = read(cdi->uffd, &msg, sizeof(msg));
		if (ret < 0) {

			if (errno == EAGAIN && !blocking){			
				
				cow_stats.eagain_errors++;
				return 0; /* No more events */
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
				if (cow_handle_write_fault(cdi, msg.arg.pagefault.address))
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

/* Background thread that monitors for write faults */
static void *cow_monitor_thread(void *arg)
{	
	struct cow_dump_info *cdi = (struct cow_dump_info *)arg;
	
	pr_info("COW monitor thread started\n");
	
	while (g_cow_info->total_pages != 0) {
		

		/* Process events with short timeout */
		if (cow_process_events(cdi, false) < 0) {
			pr_err("Error processing COW events in monitor thread\n");
			break;
		}
	}
	
	pr_info("COW monitor thread stopped\n");
	return NULL;
}

int cow_start_monitor_thread(void)
{
	int ret;
	
	if (!g_cow_info) {
		pr_err("COW dump not initialized\n");
		return -1;
	}
	
	g_stop_monitoring = false;
	
	ret = pthread_create(&g_monitor_thread, NULL, cow_monitor_thread, g_cow_info);
	if (ret) {
		pr_perror("Failed to create COW monitor thread");
		return -1;
	}
	
	pr_info("COW monitor thread created successfully\n");
	return 0;
}

int cow_stop_monitor_thread(void)
{
	void *retval;
	
	if (!g_cow_info) {
		return 0; /* Nothing to stop */
	}
	
	pr_info("Stopping COW monitor thread\n");
	g_stop_monitoring = true;
	
	/* Wait for thread to finish */
	if (pthread_join(g_monitor_thread, &retval)) {
		pr_perror("Failed to join COW monitor thread");
		return -1;
	}
	
	pr_info("COW monitor thread stopped successfully\n");
	return 0;
}

int cow_get_uffd(void)
{
	if (!g_cow_info)
		return -1;
	
	return g_cow_info->uffd;
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

	pthread_mutex_lock(&g_cow_info->cow_hash_lock);
	
	hlist_for_each_entry_safe(cp, n, &g_cow_info->cow_hash[hash], hash) {
		if (cp->vaddr == page_addr) {
			hlist_del(&cp->hash);
			pthread_mutex_unlock(&g_cow_info->cow_hash_lock);
			pr_debug("Found and removed COW page at 0x%lx from hash bucket %u\n", 
				 page_addr, hash);
			return cp;
		}
	}
	
	pthread_mutex_unlock(&g_cow_info->cow_hash_lock);
	return NULL;
}
